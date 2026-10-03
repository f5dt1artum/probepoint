import json
import struct
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_OBJECT = 1
STT_FUNC = 2

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

EM_ARM = 40
EM_386 = 3


def info(bind: int, stype: int = STT_FUNC) -> int:
    return (bind << 4) | stype


def build_strtab(strings: list[bytes]) -> tuple[bytes, dict[bytes, int]]:
    """Lay out a NUL-prefixed string table; returns (blob, offsets)."""
    blob = bytearray(b"\0")
    offsets: dict[bytes, int] = {}
    for value in strings:
        offsets[value] = len(blob)
        blob += value + b"\0"
    return bytes(blob), offsets


def build_symtab(entries: list[tuple]) -> bytes:
    """Each entry: (st_name_offset, st_value, st_size, st_info, st_shndx)."""
    blob = bytearray()
    for name, value, size, st_info, shndx in entries:
        blob += struct.pack("<IIIBBH", name, value, size, st_info, 0, shndx)
    return bytes(blob)


def assemble_elf(
    sections: list[dict],
    *,
    machine: int = EM_ARM,
    ei_class: int = 1,
    ei_data: int = 1,
    shnum_override: int | None = None,
    shentsize: int = 40,
) -> bytes:
    """Assemble a minimal 32-bit little-endian ELF.

    ``sections`` entries carry ``type``, ``data``, optional ``link``,
    ``entsize`` and an absolute ``offset`` override for corruption tests.
    Section data is laid out back-to-back right after the 52-byte header.
    A null section header is always emitted as section 0.
    """
    cursor = 52
    laid_out: list[dict] = []
    for section in sections:
        section = dict(section)
        section.setdefault("offset", cursor)
        cursor += len(section["data"])
        laid_out.append(section)
    shoff = cursor
    count = len(laid_out) + 1

    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1]) + b"\0" * 9
    ehdr = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        1,  # e_type ET_REL
        machine,
        1,  # e_version
        0,  # e_entry
        0,  # e_phoff
        shoff,
        0,  # e_flags
        52,  # e_ehsize
        0,  # e_phentsize
        0,  # e_phnum
        shentsize,
        shnum_override if shnum_override is not None else count,
        0,  # e_shstrndx
    )

    parts = [ehdr]
    for section in laid_out:
        padding = section["offset"] - sum(len(p) for p in parts)
        if padding > 0:
            parts.append(b"\0" * padding)
        parts.append(section["data"])

    shdr_blob = bytearray(40)  # section 0: SHN_UNDEF
    for index, section in enumerate(laid_out, start=1):
        shdr_blob += struct.pack(
            "<IIIIIIIIII",
            0,  # sh_name
            section["type"],
            0,  # sh_flags
            section.get("addr", 0),
            section["offset"],
            len(section["data"]),
            section.get("link", 0),
            0,  # sh_info
            1,  # sh_addralign
            section.get("entsize", 0),
        )
    parts.append(bytes(shdr_blob))
    return b"".join(parts)


def symbol_sections(
    symtab: list[tuple] = (),
    dynsym: list[tuple] = (),
    *,
    symtab_names: list[bytes] | None = None,
    dynsym_names: list[bytes] | None = None,
    symtab_link: int | None = None,
    dynsym_link: int | None = None,
    extra_symtab_bytes: bytes = b"",
    extra_dynsym_bytes: bytes = b"",
) -> list[dict]:
    """Build the standard null/strtab/symtab/dynstr/dynsym section list."""
    sections: list[dict] = []
    if symtab:
        strings = symtab_names if symtab_names is not None else [e[0] for e in symtab]
        strtab, offsets = build_strtab(strings)
        named = [
            (
                offsets[name] if isinstance(name, bytes) else name,
                value,
                size,
                st_info,
                shndx,
            )
            for name, value, size, st_info, shndx in symtab
        ]
        sections.append({"type": SHT_STRTAB, "data": strtab})  # section 1
        sections.append(
            {
                "type": SHT_SYMTAB,
                "data": build_symtab(named) + extra_symtab_bytes,
                "link": 1 if symtab_link is None else symtab_link,
                "entsize": 16,
            }
        )  # section 2
    if dynsym:
        strings = dynsym_names if dynsym_names is not None else [e[0] for e in dynsym]
        dynstr, offsets = build_strtab(strings)
        base = len(sections)
        named = [
            (
                offsets[name] if isinstance(name, bytes) else name,
                value,
                size,
                st_info,
                shndx,
            )
            for name, value, size, st_info, shndx in dynsym
        ]
        sections.append({"type": SHT_STRTAB, "data": dynstr})
        sections.append(
            {
                "type": SHT_DYNSYM,
                "data": build_symtab(named) + extra_dynsym_bytes,
                "link": base + 1 if dynsym_link is None else dynsym_link,
                "entsize": 16,
            }
        )
    return sections


# (name, value, size, info, shndx) tuples used across tests.
FUNC_FOO = (b"foo", 0x08000000, 0x10, info(STB_GLOBAL), 1)
FUNC_BAR = (b"bar", 0x08000100, 0x20, info(STB_WEAK), 1)
FUNC_LOCAL = (b"local_fn", 0x08000200, 0x08, info(STB_LOCAL), 1)


class ResolveHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        import threading

        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def post(self, path: str, raw: bytes) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def resolve(self, elf: bytes, addresses, include_local: bool = False) -> tuple[int, dict]:
        body = {"elf": elf.hex(), "addresses": addresses, "include_local": include_local}
        return self.post("/v1/symbols/resolve", json.dumps(body).encode("utf-8"))


class ResolutionTest(ResolveHttpTest):
    def test_hit_offset_and_miss(self) -> None:
        elf = assemble_elf(symbol_sections(symtab=[FUNC_FOO, FUNC_BAR]))
        status, body = self.resolve(elf, [0x08000004, 0x08000100, 0x08000300])
        self.assertEqual(status, 200)
        results = body["results"]
        self.assertEqual(
            results[0],
            {
                "address": 0x08000004,
                "name": "foo",
                "symbol_address": 0x08000000,
                "offset": 4,
                "size": 0x10,
                "binding": "global",
            },
        )
        self.assertEqual(results[1]["name"], "bar")
        self.assertEqual(results[1]["offset"], 0)
        self.assertEqual(results[1]["binding"], "weak")
        miss = results[2]
        self.assertEqual(
            miss,
            {
                "address": 0x08000300,
                "name": None,
                "symbol_address": None,
                "offset": None,
                "size": None,
                "binding": None,
            },
        )

    def test_address_at_end_of_range_is_a_miss(self) -> None:
        elf = assemble_elf(symbol_sections(symtab=[FUNC_FOO]))
        status, body = self.resolve(elf, [0x08000010])  # start + size
        self.assertEqual(status, 200)
        self.assertIsNone(body["results"][0]["name"])

    def test_thumb_bit_cleared_on_both_sides(self) -> None:
        thumb_func = (b"thumb_fn", 0x08000001, 0x10, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[thumb_func]))
        status, body = self.resolve(elf, [0x08000003, 0x08000000])
        self.assertEqual(status, 200)
        first = body["results"][0]
        self.assertEqual(first["name"], "thumb_fn")
        self.assertEqual(first["symbol_address"], 0x08000000)
        self.assertEqual(first["offset"], 2)
        self.assertEqual(body["results"][1]["offset"], 0)

    def test_order_and_duplicates_preserved(self) -> None:
        elf = assemble_elf(symbol_sections(symtab=[FUNC_FOO, FUNC_BAR]))
        addresses = [0x08000100, 0x08000000, 0x08000100]
        status, body = self.resolve(elf, addresses)
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["address"] for item in body["results"]], addresses
        )
        self.assertEqual([item["name"] for item in body["results"]], ["bar", "foo", "bar"])

    def test_local_symbol_filter(self) -> None:
        elf = assemble_elf(symbol_sections(symtab=[FUNC_LOCAL]))
        status, body = self.resolve(elf, [0x08000200], include_local=False)
        self.assertEqual(status, 200)
        self.assertIsNone(body["results"][0]["name"])

        status, body = self.resolve(elf, [0x08000204], include_local=True)
        self.assertEqual(status, 200)
        hit = body["results"][0]
        self.assertEqual(hit["name"], "local_fn")
        self.assertEqual(hit["binding"], "local")
        self.assertEqual(hit["offset"], 4)

    def test_only_defined_nonempty_named_funcs_with_size_are_used(self) -> None:
        entries = [
            (b"obj", 0x08000000, 0x10, info(STB_GLOBAL, STT_OBJECT), 1),  # not FUNC
            (b"undef", 0x08000000, 0x10, info(STB_GLOBAL), 0),  # SHN_UNDEF
            (b"zero", 0x08000000, 0, info(STB_GLOBAL), 1),  # size zero
            (b"", 0x08000000, 0x10, info(STB_GLOBAL), 1),  # empty name
        ]
        elf = assemble_elf(symbol_sections(symtab=entries))
        status, body = self.resolve(elf, [0x08000004], include_local=True)
        self.assertEqual(status, 200)
        self.assertIsNone(body["results"][0]["name"])

    def test_greatest_start_wins_for_nested_ranges(self) -> None:
        outer = (b"outer", 0x08000000, 0x100, info(STB_GLOBAL), 1)
        middle = (b"middle", 0x08000100, 0x80, info(STB_WEAK), 1)
        inner = (b"inner", 0x08000110, 0x10, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[outer, middle, inner]))
        status, body = self.resolve(elf, [0x08000114])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "inner")

    def test_binding_precedence_at_same_start(self) -> None:
        weak_one = (b"weak_one", 0x08000000, 0x20, info(STB_WEAK), 1)
        global_one = (b"global_one", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        local_one = (b"local_one", 0x08000000, 0x20, info(STB_LOCAL), 1)
        # Locals must be admitted for the comparison to happen.
        elf = assemble_elf(symbol_sections(symtab=[weak_one, local_one, global_one]))
        status, body = self.resolve(elf, [0x08000008], include_local=True)
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "global_one")

        status, body = self.resolve(elf, [0x08000008], include_local=False)
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "global_one")

    def test_weak_beats_local(self) -> None:
        local_one = (b"local_one", 0x08000000, 0x20, info(STB_LOCAL), 1)
        weak_one = (b"weak_one", 0x08000000, 0x20, info(STB_WEAK), 1)
        elf = assemble_elf(symbol_sections(symtab=[local_one, weak_one]))
        status, body = self.resolve(elf, [0x08000008], include_local=True)
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "weak_one")

    def test_smaller_range_wins_on_tie(self) -> None:
        big = (b"big", 0x08000000, 0x40, info(STB_GLOBAL), 1)
        small = (b"small", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[big, small]))
        status, body = self.resolve(elf, [0x08000010])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "small")

    def test_entry_index_wins_final_tie(self) -> None:
        first = (b"first", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        second = (b"second", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[first, second]))
        status, body = self.resolve(elf, [0x08000008])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "first")

    def test_dynsym_is_searched(self) -> None:
        elf = assemble_elf(symbol_sections(dynsym=[FUNC_BAR]))
        status, body = self.resolve(elf, [0x08000104])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "bar")

    def test_symtab_section_beats_dynsym_section_on_full_tie(self) -> None:
        # symtab lands at section 2, dynsym at section 4; identical
        # start/size/binding leaves the table section index as tie-break.
        sym = (b"from_symtab", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        dyn = (b"from_dynsym", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[sym], dynsym=[dyn]))
        status, body = self.resolve(elf, [0x08000004])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "from_symtab")

    def test_global_in_dynsym_beats_weak_in_symtab(self) -> None:
        sym = (b"weak_sym", 0x08000000, 0x20, info(STB_WEAK), 1)
        dyn = (b"global_dyn", 0x08000000, 0x20, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[sym], dynsym=[dyn]))
        status, body = self.resolve(elf, [0x08000004])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "global_dyn")

    def test_utf8_names_pass_through(self) -> None:
        func = ("ünïcode_ƒ".encode("utf-8"), 0x08000000, 0x10, info(STB_GLOBAL), 1)
        elf = assemble_elf(symbol_sections(symtab=[func]))
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["name"], "ünïcode_ƒ")


class ElfValidationTest(ResolveHttpTest):
    def test_no_symbol_tables(self) -> None:
        elf = assemble_elf([])
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "symbol_table_not_found")

    def test_only_strtab_is_not_a_symbol_table(self) -> None:
        elf = assemble_elf([{"type": SHT_STRTAB, "data": b"\0foo\0"}])
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "symbol_table_not_found")

    def test_unsupported_class(self) -> None:
        symtab = symbol_sections(symtab=[FUNC_FOO])
        elf = assemble_elf(symtab, ei_class=2)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "unsupported_elf")

    def test_unsupported_endianness(self) -> None:
        symtab = symbol_sections(symtab=[FUNC_FOO])
        elf = assemble_elf(symtab, ei_data=2)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "unsupported_elf")

    def test_unsupported_machine(self) -> None:
        symtab = symbol_sections(symtab=[FUNC_FOO])
        elf = assemble_elf(symtab, machine=EM_386)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "unsupported_elf")

    def test_bad_magic(self) -> None:
        symtab = symbol_sections(symtab=[FUNC_FOO])
        elf = bytearray(assemble_elf(symtab))
        elf[0:4] = b"NOPE"
        status, body = self.resolve(bytes(elf), [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_truncated_header(self) -> None:
        status, body = self.resolve(b"\x7fELF\x01\x01\x01", [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_section_data_out_of_range(self) -> None:
        sections = symbol_sections(symtab=[FUNC_FOO])
        elf = bytearray(assemble_elf(sections))
        # Section 1 (the strtab) header starts 40 bytes into the header
        # table; sh_offset is at +16 within a section header.
        shoff = struct.unpack_from("<I", elf, 32)[0]
        patched_offset = len(elf) + 100
        struct.pack_into("<I", elf, shoff + 40 + 16, patched_offset)
        status, body = self.resolve(bytes(elf), [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_section_header_table_truncated(self) -> None:
        elf = assemble_elf(symbol_sections(symtab=[FUNC_FOO]), shnum_override=10)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_symbol_name_past_strtab(self) -> None:
        # A raw integer name offset bypasses the builder's name table.
        entries = [(999, 0x08000000, 0x10, info(STB_GLOBAL), 1)]
        elf = assemble_elf(symbol_sections(symtab=entries, symtab_names=[b"foo"]))
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_symbol_name_invalid_utf8(self) -> None:
        bad = b"\xff\xfe"
        entries = [(bad, 0x08000000, 0x10, info(STB_GLOBAL), 1)]
        elf = assemble_elf(symbol_sections(symtab=entries))
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_symbol_range_overflow(self) -> None:
        # Value with the Thumb bit set clears to 0xFFFFFFFE; +4 overflows.
        entries = [(b"edge", 0xFFFFFFFF, 4, info(STB_GLOBAL), 1)]
        elf = assemble_elf(symbol_sections(symtab=entries))
        status, body = self.resolve(elf, [0xFFFFFFFE])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_partial_symtab_entry(self) -> None:
        sections = symbol_sections(symtab=[FUNC_FOO], extra_symtab_bytes=b"\x00" * 7)
        elf = assemble_elf(sections)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_symtab_link_out_of_range(self) -> None:
        sections = symbol_sections(symtab=[FUNC_FOO], symtab_link=99)
        elf = assemble_elf(sections)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_symtab_link_not_a_strtab(self) -> None:
        # Section layout: 1 STRTAB, 2 SYMTAB(link 1), 3 STRTAB, 4 DYNSYM.
        # Repoint the SYMTAB link at the DYNSYM section (index 4).
        sections = symbol_sections(symtab=[FUNC_FOO], dynsym=[FUNC_BAR], symtab_link=4)
        elf = assemble_elf(sections)
        status, body = self.resolve(elf, [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")

    def test_empty_file(self) -> None:
        status, body = self.resolve(b"", [0x08000000])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_elf")


class RequestValidationTest(ResolveHttpTest):
    VALID_ELF = None  # built lazily; class attribute set in setUpClass-free use

    def valid_body(self) -> dict:
        elf = assemble_elf(symbol_sections(symtab=[FUNC_FOO]))
        return {"elf": elf.hex(), "addresses": [0x08000000], "include_local": False}

    def resolve_body(self, body: object) -> tuple[int, dict]:
        return self.post("/v1/symbols/resolve", json.dumps(body).encode("utf-8"))

    def assert_invalid_field(self, body: object) -> None:
        status, response = self.resolve_body(body)
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], "invalid_field")

    def test_non_object_body(self) -> None:
        for raw in (b"[1, 2, 3]", b'"hello"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, body = self.post("/v1/symbols/resolve", raw)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_request")

    def test_unparseable_body(self) -> None:
        status, body = self.post("/v1/symbols/resolve", b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_missing_and_extra_fields(self) -> None:
        for dropped in ("elf", "addresses", "include_local"):
            body = self.valid_body()
            del body[dropped]
            self.assert_invalid_field(body)
        body = self.valid_body()
        body["bogus"] = 1
        self.assert_invalid_field(body)

    def test_elf_field(self) -> None:
        body = self.valid_body()
        body["elf"] = 123
        self.assert_invalid_field(body)
        body = self.valid_body()
        body["elf"] = "abc"  # odd length
        self.assert_invalid_field(body)
        body = self.valid_body()
        body["elf"] = "zz"
        self.assert_invalid_field(body)

    def test_elf_size_limit(self) -> None:
        body = self.valid_body()
        body["elf"] = "00" * (4 * 1024 * 1024 + 1)
        self.assert_invalid_field(body)
        # Exactly at the limit is accepted structurally (then fails as ELF).
        body = self.valid_body()
        body["elf"] = "00" * (4 * 1024 * 1024)
        status, response = self.resolve_body(body)
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], "invalid_elf")

    def test_addresses_field(self) -> None:
        good_elf = self.valid_body()["elf"]

        def body_with(addresses: object) -> dict:
            return {"elf": good_elf, "addresses": addresses, "include_local": False}

        self.assert_invalid_field(body_with([]))
        self.assert_invalid_field(body_with([0] * 257))
        self.assert_invalid_field(body_with("08000000"))
        self.assert_invalid_field(body_with({}))
        self.assert_invalid_field(body_with([True]))
        self.assert_invalid_field(body_with(["8"]))
        self.assert_invalid_field(body_with([-1]))
        self.assert_invalid_field(body_with([1 << 32]))
        self.assert_invalid_field(body_with([None]))

    def test_addresses_limit_boundary(self) -> None:
        body = self.valid_body()
        body["addresses"] = [0x08000000] * 256
        status, response = self.resolve_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(len(response["results"]), 256)

    def test_include_local_must_be_bool(self) -> None:
        for value in (0, 1, "true", None):
            body = self.valid_body()
            body["include_local"] = value
            self.assert_invalid_field(body)

    def test_empty_hex_elf_is_invalid_elf_not_field_error(self) -> None:
        body = {"elf": "", "addresses": [0], "include_local": False}
        status, response = self.resolve_body(body)
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], "invalid_elf")


class StatelessnessTest(ResolveHttpTest):
    def test_resolve_does_not_touch_breakpoints(self) -> None:
        status, created = self.post(
            "/v1/breakpoints",
            json.dumps({"kind": "execute", "address": 0x08000000, "enabled": True}).encode(),
        )
        self.assertEqual(status, 201)
        elf = assemble_elf(symbol_sections(symtab=[FUNC_FOO]))
        status, _ = self.resolve(elf, [0x08000000, 0x08000000])
        self.assertEqual(status, 200)
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/breakpoints")
        with urllib.request.urlopen(req) as resp:
            listed = json.loads(resp.read())
        self.assertEqual(listed, [created])

    def test_backtrace_route_unchanged(self) -> None:
        # A malformed backtrace body still reports the backtrace surface's
        # own error code, proving route wiring was not disturbed.
        status, body = self.post("/v1/backtrace", b"{}")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")


if __name__ == "__main__":
    unittest.main()
