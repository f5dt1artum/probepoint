import json
import struct
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_FUNC = 2
STT_OBJECT = 1


def _symtab_bytes(symbols):
    """Render a symbol table plus its string table.

    Each symbol is a dict with keys value/size and optional name, bind,
    type, shndx and raw_name (bytes, to inject invalid UTF-8).
    """
    strtab = bytearray(b"\x00")
    data = bytearray(b"\x00" * 16)  # mandatory null symbol
    for symbol in symbols:
        if "name" not in symbol and "raw_name" not in symbol:
            name_offset = 0
        else:
            name_offset = len(strtab)
            raw = symbol.get("raw_name")
            if raw is None:
                raw = symbol["name"].encode("utf-8")
            strtab += raw + b"\x00"
        info = (symbol.get("bind", STB_GLOBAL) << 4) | symbol.get("type", STT_FUNC)
        data += struct.pack(
            "<IIIBBH",
            name_offset,
            symbol["value"],
            symbol["size"],
            info,
            0,
            symbol.get("shndx", 1),
        )
    return bytes(data), bytes(strtab)


def make_elf(symtab=None, dynsym=None, *, machine=0x28, ei_class=1, ei_data=1):
    """Build a minimal ELF32 image with the given symbol tables."""
    sections = [(0, b"", 0, 0)]  # (sh_type, data, sh_link, sh_entsize); null section
    if symtab is not None:
        sym_data, str_data = _symtab_bytes(symtab)
        sections.append((2, sym_data, len(sections) + 1, 16))
        sections.append((3, str_data, 0, 0))
    if dynsym is not None:
        sym_data, str_data = _symtab_bytes(dynsym)
        sections.append((11, sym_data, len(sections) + 1, 16))
        sections.append((3, str_data, 0, 0))

    offset = 52
    body = bytearray()
    headers = []
    for sh_type, data, sh_link, sh_entsize in sections:
        if sh_type == 0:
            headers.append((0, 0, 0, 0, 0))
            continue
        while offset % 4:
            body += b"\x00"
            offset += 1
        headers.append((sh_type, offset, len(data), sh_link, sh_entsize))
        body += data
        offset += len(data)
    while offset % 4:
        body += b"\x00"
        offset += 1
    e_shoff = offset
    shbytes = b"".join(
        struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, sh_offset, sh_size, sh_link, 0, 0, sh_entsize)
        for sh_type, sh_offset, sh_size, sh_link, sh_entsize in headers
    )
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, ei_class, ei_data, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH", 2, machine, 1, 0, 0, e_shoff, 0, 52, 0, 0, 40, len(sections), 0
    )
    return bytes(header + body + shbytes)


def request_body(elf, addresses, include_local=False):
    return json.dumps(
        {"elf": elf.hex(), "addresses": addresses, "include_local": include_local}
    ).encode()


class SymbolsResolveHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        import threading

        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def post(self, raw):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/symbols/resolve",
            data=raw,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def resolve(self, elf, addresses, include_local=False):
        status, payload = self.post(request_body(elf, addresses, include_local))
        self.assertEqual(status, 200, payload)
        return payload["results"]

    def assert_error(self, raw, status, code):
        actual_status, payload = self.post(raw)
        self.assertEqual(actual_status, status, payload)
        self.assertEqual(payload["error"]["code"], code)

    def test_hit_clears_thumb_bit_and_reports_offset(self):
        elf = make_elf(symtab=[{"name": "Reset_Handler", "value": 0x08000101, "size": 0x40}])
        (result,) = self.resolve(elf, [0x08000121])
        self.assertEqual(result["address"], 0x08000121)
        self.assertEqual(result["name"], "Reset_Handler")
        self.assertEqual(result["symbol_address"], 0x08000100)
        self.assertEqual(result["offset"], 0x20)
        self.assertEqual(result["size"], 0x40)
        self.assertEqual(result["binding"], "global")

    def test_miss_returns_null_fields(self):
        elf = make_elf(symtab=[{"name": "foo", "value": 0x1000, "size": 0x10}])
        (result,) = self.resolve(elf, [0x2000])
        self.assertEqual(result["address"], 0x2000)
        for key in ("name", "symbol_address", "offset", "size", "binding"):
            self.assertIsNone(result[key], key)

    def test_range_end_is_exclusive(self):
        elf = make_elf(symtab=[{"name": "foo", "value": 0x1000, "size": 0x10}])
        (result,) = self.resolve(elf, [0x1010])
        self.assertIsNone(result["name"])

    def test_local_excluded_unless_requested(self):
        elf = make_elf(
            symtab=[{"name": "static_fn", "value": 0x1000, "size": 0x10, "bind": STB_LOCAL}]
        )
        (result,) = self.resolve(elf, [0x1004], include_local=False)
        self.assertIsNone(result["name"])
        (result,) = self.resolve(elf, [0x1004], include_local=True)
        self.assertEqual(result["name"], "static_fn")
        self.assertEqual(result["binding"], "local")

    def test_weak_binding_reported(self):
        elf = make_elf(
            symtab=[{"name": "weak_fn", "value": 0x1000, "size": 0x10, "bind": STB_WEAK}]
        )
        (result,) = self.resolve(elf, [0x1000])
        self.assertEqual(result["binding"], "weak")

    def test_tiebreak_prefers_largest_start(self):
        elf = make_elf(
            symtab=[
                {"name": "outer", "value": 0x1000, "size": 0x100},
                {"name": "inner", "value": 0x1040, "size": 0x10},
            ]
        )
        (result,) = self.resolve(elf, [0x1044])
        self.assertEqual(result["name"], "inner")

    def test_tiebreak_prefers_global_over_weak_over_local(self):
        elf = make_elf(
            symtab=[
                {"name": "as_local", "value": 0x1000, "size": 0x10, "bind": STB_LOCAL},
                {"name": "as_weak", "value": 0x1000, "size": 0x10, "bind": STB_WEAK},
                {"name": "as_global", "value": 0x1000, "size": 0x10, "bind": STB_GLOBAL},
            ]
        )
        (result,) = self.resolve(elf, [0x1000], include_local=True)
        self.assertEqual(result["name"], "as_global")
        elf = make_elf(
            symtab=[
                {"name": "as_local", "value": 0x1000, "size": 0x10, "bind": STB_LOCAL},
                {"name": "as_weak", "value": 0x1000, "size": 0x10, "bind": STB_WEAK},
            ]
        )
        (result,) = self.resolve(elf, [0x1000], include_local=True)
        self.assertEqual(result["name"], "as_weak")

    def test_tiebreak_prefers_smaller_range(self):
        elf = make_elf(
            symtab=[
                {"name": "wide", "value": 0x1000, "size": 0x80},
                {"name": "narrow", "value": 0x1000, "size": 0x20},
            ]
        )
        (result,) = self.resolve(elf, [0x1004])
        self.assertEqual(result["name"], "narrow")

    def test_dynsym_only_image(self):
        elf = make_elf(dynsym=[{"name": "dyn_fn", "value": 0x2000, "size": 0x20}])
        (result,) = self.resolve(elf, [0x2010])
        self.assertEqual(result["name"], "dyn_fn")

    def test_both_tables_contribute_and_section_order_breaks_ties(self):
        elf = make_elf(
            symtab=[{"name": "from_symtab", "value": 0x1000, "size": 0x10}],
            dynsym=[{"name": "from_dynsym", "value": 0x1000, "size": 0x10}],
        )
        (result,) = self.resolve(elf, [0x1000])
        self.assertEqual(result["name"], "from_symtab")

    def test_non_function_and_undefined_and_zero_size_symbols_ignored(self):
        elf = make_elf(
            symtab=[
                {"name": "obj", "value": 0x1000, "size": 0x10, "type": STT_OBJECT},
                {"name": "undef", "value": 0x1000, "size": 0x10, "shndx": 0},
                {"name": "empty", "value": 0x1000, "size": 0},
                {"name": "real", "value": 0x1000, "size": 0x10},
            ]
        )
        (result,) = self.resolve(elf, [0x1000])
        self.assertEqual(result["name"], "real")

    def test_order_and_duplicates_preserved(self):
        elf = make_elf(symtab=[{"name": "foo", "value": 0x1000, "size": 0x10}])
        results = self.resolve(elf, [0x2000, 0x1000, 0x1000])
        self.assertEqual([r["address"] for r in results], [0x2000, 0x1000, 0x1000])
        self.assertIsNone(results[0]["name"])
        self.assertEqual(results[1]["name"], "foo")
        self.assertEqual(results[2]["name"], "foo")

    def test_invalid_request_when_body_not_object(self):
        self.assert_error(b"[1, 2, 3]", 400, "invalid_request")

    def test_invalid_field_on_missing_and_extra_fields(self):
        elf = make_elf(symtab=[])
        self.assert_error(
            json.dumps({"elf": elf.hex(), "addresses": [1]}).encode(), 400, "invalid_field"
        )
        self.assert_error(
            json.dumps(
                {
                    "elf": elf.hex(),
                    "addresses": [1],
                    "include_local": False,
                    "extra": 1,
                }
            ).encode(),
            400,
            "invalid_field",
        )

    def test_invalid_field_on_bad_hex_and_types(self):
        elf = make_elf(symtab=[])
        good = {"elf": elf.hex(), "addresses": [1], "include_local": False}
        for patch in (
            {"elf": "abc"},  # odd length
            {"elf": "zz"},
            {"elf": 12},
            {"addresses": "1000"},
            {"addresses": []},
            {"addresses": list(range(257))},
            {"addresses": [-1]},
            {"addresses": [1 << 32]},
            {"addresses": [True]},
            {"include_local": 0},
        ):
            body = dict(good)
            body.update(patch)
            self.assert_error(json.dumps(body).encode(), 400, "invalid_field")

    def test_invalid_field_on_oversized_elf(self):
        elf = b"\x7fELF" + b"\x00" * (4 * 1024 * 1024 - 4 + 2)
        body = {"elf": elf.hex(), "addresses": [0], "include_local": False}
        self.assert_error(json.dumps(body).encode(), 400, "invalid_field")

    def test_invalid_elf_on_truncated_and_bad_magic(self):
        self.assert_error(request_body(b"\x7fELF\x01", [0]), 400, "invalid_elf")
        elf = bytearray(make_elf(symtab=[]))
        elf[0] = 0x00
        self.assert_error(request_body(bytes(elf), [0]), 400, "invalid_elf")

    def test_unsupported_elf_on_class_data_machine(self):
        base = make_elf(symtab=[])
        for kwargs in ({"ei_class": 2}, {"ei_data": 2}, {"machine": 0x03}):
            self.assert_error(
                request_body(make_elf(symtab=[], **kwargs), [0]), 422, "unsupported_elf"
            )

    def test_symbol_table_not_found(self):
        elf = make_elf()
        self.assert_error(request_body(elf, [0]), 422, "symbol_table_not_found")

    def test_invalid_elf_on_bad_string_reference(self):
        elf = bytearray(make_elf(symtab=[{"name": "foo", "value": 0x1000, "size": 0x10}]))
        # First real symbol starts right after the ELF header + null symbol.
        st_name_offset = 52 + 16
        struct.pack_into("<I", elf, st_name_offset, 0xFFFF00)
        self.assert_error(request_body(bytes(elf), [0x1000]), 400, "invalid_elf")

    def test_invalid_elf_on_non_utf8_name(self):
        elf = make_elf(symtab=[{"raw_name": b"\xff\xfe", "value": 0x1000, "size": 0x10}])
        self.assert_error(request_body(elf, [0x1000]), 400, "invalid_elf")

    def test_invalid_elf_on_symbol_range_overflow(self):
        elf = make_elf(symtab=[{"name": "foo", "value": 0xFFFFFFF0, "size": 0x40}])
        self.assert_error(request_body(elf, [0xFFFFFFF0]), 400, "invalid_elf")

    def test_invalid_elf_on_out_of_range_section_link(self):
        elf = bytearray(make_elf(symtab=[{"name": "foo", "value": 0x1000, "size": 0x10}]))
        e_shoff = struct.unpack_from("<I", elf, 32)[0]
        # Symtab is section 1; sh_link sits at offset 24 of its header.
        struct.pack_into("<I", elf, e_shoff + 40 + 24, 99)
        self.assert_error(request_body(bytes(elf), [0x1000]), 400, "invalid_elf")

    def test_backtrace_route_still_works(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/backtrace",
            data=json.dumps(
                {
                    "pc": 0x100,
                    "sp": 0x20000000,
                    "frame_pointer": 0,
                    "stack_base": 0x20000000,
                    "stack": "",
                    "symbols": [],
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            payload = json.loads(resp.read())
        self.assertEqual(payload["stop_reason"], "complete")


if __name__ == "__main__":
    unittest.main()
