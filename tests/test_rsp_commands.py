import json
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server

ENCODE_PATH = "/v1/rsp/commands/encode"
RESPONSE_PATH = "/v1/rsp/commands/decode-response"
PACKET_ENCODE_PATH = "/v1/rsp/encode"
STREAM_PATH = "/v1/rsp/decode-stream"

READ_MEMORY = "read_memory"
WRITE_MEMORY = "write_memory"
READ_REGISTER = "read_register"
WRITE_REGISTER = "write_register"
CONTINUE = "continue"
SINGLE_STEP = "single_step"
FLASH_ERASE = "flash_erase"
FLASH_WRITE = "flash_write"
FLASH_DONE = "flash_done"


def ascii_hex(text: str) -> str:
    """Hex of the ASCII bytes of a target reply, as decode-stream emits it."""
    return text.encode("ascii").hex()


class RspCommandsHttpTest(unittest.TestCase):
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

    def call(self, path: str, body: object) -> tuple[int, dict]:
        return self.post(path, json.dumps(body).encode("utf-8"))

    def encode(self, body: object) -> tuple[int, dict]:
        return self.call(ENCODE_PATH, body)

    def respond(self, body: object) -> tuple[int, dict]:
        return self.call(RESPONSE_PATH, body)


class EncodeCommandTest(RspCommandsHttpTest):
    def test_read_memory_basic(self) -> None:
        status, body = self.encode({"operation": READ_MEMORY, "address": 0, "length": 1})
        self.assertEqual(status, 200)
        # ASCII payload "m0,1"
        self.assertEqual(body, {"payload": "6d302c31"})

    def test_read_memory_numbers_bare_lowercase_hex(self) -> None:
        # address 10 -> a, length 255 -> ff: no leading zeros, lowercase.
        status, body = self.encode({"operation": READ_MEMORY, "address": 10, "length": 255})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"ma,ff")

    def test_read_memory_limit(self) -> None:
        status, body = self.encode({"operation": READ_MEMORY, "address": 0, "length": 4096})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"m0,1000")

    def test_write_memory_basic(self) -> None:
        status, body = self.encode(
            {"operation": WRITE_MEMORY, "address": 10, "data": "cafe"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"Ma,2:cafe")

    def test_write_memory_uppercase_input_lowercased_order_kept(self) -> None:
        status, body = self.encode(
            {"operation": WRITE_MEMORY, "address": 1, "data": "DEAD00FF"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"M1,4:dead00ff")

    def test_read_register_basic(self) -> None:
        status, body = self.encode({"operation": READ_REGISTER, "register": 0})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"p0")

    def test_read_register_max(self) -> None:
        status, body = self.encode({"operation": READ_REGISTER, "register": 0xFFFF})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"pffff")

    def test_write_register_basic(self) -> None:
        status, body = self.encode(
            {"operation": WRITE_REGISTER, "register": 1, "value": "deadbeef"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"P1=deadbeef")

    def test_write_register_max_size_and_case(self) -> None:
        status, body = self.encode(
            {"operation": WRITE_REGISTER, "register": 0xFA0, "value": "AB" * 32}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"Pfa0=" + b"ab" * 32)

    def test_address_boundary_inclusive(self) -> None:
        # One byte at 0xfffffffe ends on 0xffffffff and is allowed.
        status, body = self.encode(
            {"operation": READ_MEMORY, "address": 0xFFFFFFFE, "length": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"mfffffffe,1")
        status, body = self.encode(
            {"operation": WRITE_MEMORY, "address": 0xFFFFFFFD, "data": "00ff"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"Mfffffffd,2:00ff")

    def test_address_overflow(self) -> None:
        cases = [
            {"operation": READ_MEMORY, "address": 0xFFFFFFFF, "length": 1},
            {"operation": READ_MEMORY, "address": 0xFFFFF000, "length": 4096},
            {"operation": WRITE_MEMORY, "address": 0xFFFFFFFF, "data": "ff"},
            {"operation": WRITE_MEMORY, "address": 0xFFFFFFFE, "data": "0000"},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_field_range_errors(self) -> None:
        cases = [
            {"operation": READ_MEMORY, "address": 0, "length": 0},
            {"operation": READ_MEMORY, "address": 0, "length": 4097},
            {"operation": READ_MEMORY, "address": -1, "length": 1},
            {"operation": READ_MEMORY, "address": 1 << 32, "length": 1},
            {"operation": READ_MEMORY, "address": True, "length": 1},
            {"operation": WRITE_MEMORY, "address": 0, "data": ""},
            {"operation": WRITE_MEMORY, "address": 0, "data": "00" * 4097},
            {"operation": WRITE_MEMORY, "address": 0, "data": "abc"},
            {"operation": WRITE_MEMORY, "address": 0, "data": "0x00"},
            {"operation": WRITE_MEMORY, "address": 0, "data": "zz"},
            {"operation": READ_REGISTER, "register": 1 << 16},
            {"operation": READ_REGISTER, "register": -1},
            {"operation": WRITE_REGISTER, "register": 0, "value": ""},
            {"operation": WRITE_REGISTER, "register": 0, "value": "ab" * 33},
            {"operation": WRITE_REGISTER, "register": 0, "value": "abc"},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_missing_extra_and_unknown_operation(self) -> None:
        cases = [
            {},
            {"address": 0, "length": 1},  # missing operation
            {"operation": READ_MEMORY, "address": 0},  # missing length
            {"operation": READ_REGISTER, "register": 0, "value": "ab"},  # extra
            {"operation": READ_MEMORY, "address": 0, "length": 1, "data": "ab"},
            {"operation": WRITE_MEMORY, "address": 0, "data": "ab", "length": 1},
            {"operation": WRITE_MEMORY, "address": 0, "data": "ab", "extra": 1},
            {"operation": "read_io", "address": 0, "length": 1},
            {"operation": 4, "register": 0},
            {"operation": None},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_not_json_object(self) -> None:
        for raw in (b"not json", b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(ENCODE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_payload_round_trips_through_packet_codec(self) -> None:
        # commands/encode -> rsp/encode -> rsp/decode-stream yields the same
        # command payload and decodes as a wire packet.
        status, enc = self.encode(
            {"operation": WRITE_MEMORY, "address": 0x100, "data": "cafe"}
        )
        self.assertEqual(status, 200)
        command_payload = enc["payload"]

        status, packet = self.call(PACKET_ENCODE_PATH, {"payload": command_payload})
        self.assertEqual(status, 200)
        status, stream = self.call(STREAM_PATH, {"data": packet["packet"], "eof": True})
        self.assertEqual(status, 200)
        self.assertEqual(
            [p["payload"] for p in stream["packets"]], [command_payload]
        )


class EncodeExecutionCommandTest(RspCommandsHttpTest):
    def test_continue_without_address(self) -> None:
        status, body = self.encode({"operation": CONTINUE})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"c")

    def test_single_step_without_address(self) -> None:
        status, body = self.encode({"operation": SINGLE_STEP})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"s")

    def test_continue_with_address_zero(self) -> None:
        status, body = self.encode({"operation": CONTINUE, "address": 0})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"c0")

    def test_single_step_with_address_zero(self) -> None:
        status, body = self.encode({"operation": SINGLE_STEP, "address": 0})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"s0")

    def test_address_bare_lowercase_hex(self) -> None:
        status, body = self.encode({"operation": CONTINUE, "address": 0xABCDEF})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"cabcdef")

    def test_address_max(self) -> None:
        for operation in (CONTINUE, SINGLE_STEP):
            with self.subTest(operation=operation):
                status, body = self.encode({"operation": operation, "address": 0xFFFFFFFF})
                self.assertEqual(status, 200)
                self.assertEqual(
                    bytes.fromhex(body["payload"]),
                    b"cffffffff" if operation == CONTINUE else b"sffffffff",
                )

    def test_address_errors(self) -> None:
        cases = [
            {"operation": CONTINUE, "address": -1},
            {"operation": CONTINUE, "address": 1 << 32},
            {"operation": SINGLE_STEP, "address": True},
            {"operation": SINGLE_STEP, "address": "10"},
            {"operation": SINGLE_STEP, "address": None},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_extra_fields(self) -> None:
        cases = [
            {"operation": CONTINUE, "length": 1},
            {"operation": CONTINUE, "data": "ab"},
            {"operation": CONTINUE, "register": 0},
            {"operation": SINGLE_STEP, "address": 0, "expected_length": 1},
            {"operation": SINGLE_STEP, "address": 0, "extra": 1},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")


class EncodeFlashCommandTest(RspCommandsHttpTest):
    def test_flash_erase_basic(self) -> None:
        status, body = self.encode(
            {"operation": FLASH_ERASE, "address": 0x1000, "length": 0x2000}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashErase:1000,2000")

    def test_flash_erase_numbers_bare_lowercase_hex(self) -> None:
        status, body = self.encode(
            {"operation": FLASH_ERASE, "address": 10, "length": 255}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashErase:a,ff")

    def test_flash_erase_length_max_and_full_space(self) -> None:
        # length spans the whole u32 range starting at address 0.
        status, body = self.encode(
            {"operation": FLASH_ERASE, "address": 0, "length": 0xFFFFFFFF}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashErase:0,ffffffff")
        # Half-open interval ending exactly on 0xffffffff is allowed.
        status, body = self.encode(
            {"operation": FLASH_ERASE, "address": 0xFFFFFFFE, "length": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashErase:fffffffe,1")

    def test_flash_erase_errors(self) -> None:
        cases = [
            {"operation": FLASH_ERASE, "address": 0, "length": 0},
            {"operation": FLASH_ERASE, "address": 0, "length": 1 << 32},
            {"operation": FLASH_ERASE, "address": -1, "length": 1},
            {"operation": FLASH_ERASE, "address": 1 << 32, "length": 1},
            {"operation": FLASH_ERASE, "address": True, "length": 1},
            {"operation": FLASH_ERASE, "address": 0, "length": True},
            {"operation": FLASH_ERASE, "address": 0, "length": "1"},
            {"operation": FLASH_ERASE, "address": 0xFFFFFFFF, "length": 1},
            {"operation": FLASH_ERASE, "address": 0, "length": 0xFFFFFFFF + 1},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_flash_erase_rejects_extra_and_missing_fields(self) -> None:
        cases = [
            {"operation": FLASH_ERASE, "address": 0},
            {"operation": FLASH_ERASE, "length": 1},
            {"operation": FLASH_ERASE, "address": 0, "length": 1, "data": "ab"},
            {"operation": FLASH_ERASE, "address": 0, "length": 1, "extra": 1},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_flash_write_basic(self) -> None:
        status, body = self.encode(
            {"operation": FLASH_WRITE, "address": 0x100, "data": "cafe"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashWrite:100:" + bytes.fromhex("cafe"))

    def test_flash_write_address_zero(self) -> None:
        status, body = self.encode(
            {"operation": FLASH_WRITE, "address": 0, "data": "00ff"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashWrite:0:\x00\xff")

    def test_flash_write_special_bytes_are_raw_not_escaped(self) -> None:
        # 0x00 and the RSP-special bytes 0x24 '$', 0x23 '#', 0x7d '}',
        # 0x2a '*' stay as-is in the command payload; only the packet
        # codec escapes them.
        status, body = self.encode(
            {"operation": FLASH_WRITE, "address": 0, "data": "0024237d2a"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["payload"], (b"vFlashWrite:0:" + bytes([0x00, 0x24, 0x23, 0x7D, 0x2A])).hex())

    def test_flash_write_payload_limit(self) -> None:
        prefix = len("vFlashWrite:0:")
        data = "ab" * (4096 - prefix)
        status, body = self.encode({"operation": FLASH_WRITE, "address": 0, "data": data})
        self.assertEqual(status, 200)
        self.assertEqual(len(bytes.fromhex(body["payload"])), 4096)

        status, resp = self.encode(
            {"operation": FLASH_WRITE, "address": 0, "data": "ab" * (4096 - prefix + 1)}
        )
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_flash_write_address_boundary(self) -> None:
        # Half-open interval ending exactly on 0xffffffff is allowed.
        status, body = self.encode(
            {"operation": FLASH_WRITE, "address": 0xFFFFFFFE, "data": "ff"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashWrite:fffffffe:\xff")

    def test_flash_write_errors(self) -> None:
        cases = [
            {"operation": FLASH_WRITE, "address": 0xFFFFFFFF, "data": "ff"},
            {"operation": FLASH_WRITE, "address": 0xFFFFFFFF, "data": "0000"},
            {"operation": FLASH_WRITE, "address": 0xFFFFFFFE, "data": "000000"},
            {"operation": FLASH_WRITE, "address": 0, "data": ""},
            {"operation": FLASH_WRITE, "address": 0, "data": "abc"},
            {"operation": FLASH_WRITE, "address": 0, "data": "0xab"},
            {"operation": FLASH_WRITE, "address": 0, "data": "zz"},
            {"operation": FLASH_WRITE, "address": -1, "data": "ab"},
            {"operation": FLASH_WRITE, "address": 1 << 32, "data": "ab"},
            {"operation": FLASH_WRITE, "address": True, "data": "ab"},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_flash_write_rejects_extra_and_missing_fields(self) -> None:
        cases = [
            {"operation": FLASH_WRITE, "address": 0},
            {"operation": FLASH_WRITE, "data": "ab"},
            {"operation": FLASH_WRITE, "address": 0, "data": "ab", "length": 1},
            {"operation": FLASH_WRITE, "address": 0, "data": "ab", "extra": 1},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_flash_done_basic(self) -> None:
        status, body = self.encode({"operation": FLASH_DONE})
        self.assertEqual(status, 200)
        self.assertEqual(bytes.fromhex(body["payload"]), b"vFlashDone")

    def test_flash_done_rejects_extra_fields(self) -> None:
        for body in (
            {"operation": FLASH_DONE, "address": 0},
            {"operation": FLASH_DONE, "length": 1},
            {"operation": FLASH_DONE, "data": "ab"},
            {"operation": FLASH_DONE, "extra": 1},
        ):
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_flash_payload_round_trips_through_packet_codec(self) -> None:
        # vFlashWrite raw special bytes get escaped by the packet codec and
        # decode back to the exact same command payload.
        status, enc = self.encode(
            {"operation": FLASH_WRITE, "address": 0x42, "data": "0024237d2a"}
        )
        self.assertEqual(status, 200)
        command_payload = enc["payload"]
        status, packet = self.call(PACKET_ENCODE_PATH, {"payload": command_payload})
        self.assertEqual(status, 200)
        status, stream = self.call(STREAM_PATH, {"data": packet["packet"], "eof": True})
        self.assertEqual(status, 200)
        self.assertEqual([p["payload"] for p in stream["packets"]], [command_payload])

        status, enc = self.encode({"operation": FLASH_DONE})
        self.assertEqual(status, 200)
        command_payload = enc["payload"]
        status, packet = self.call(PACKET_ENCODE_PATH, {"payload": command_payload})
        self.assertEqual(status, 200)
        status, stream = self.call(STREAM_PATH, {"data": packet["packet"], "eof": True})
        self.assertEqual(status, 200)
        self.assertEqual([p["payload"] for p in stream["packets"]], [command_payload])


class DecodeCommandResponseTest(RspCommandsHttpTest):
    def test_empty_payload_is_unsupported(self) -> None:
        for body in (
            {"operation": READ_MEMORY, "payload": "", "expected_length": 1},
            {"operation": READ_REGISTER, "payload": "", "expected_size": 4},
            {"operation": WRITE_MEMORY, "payload": ""},
            {"operation": WRITE_REGISTER, "payload": ""},
        ):
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "unsupported"})

    def test_error_code(self) -> None:
        status, resp = self.respond(
            {"operation": READ_MEMORY, "payload": ascii_hex("E01"), "expected_length": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "error", "code": "01"})

    def test_error_code_lowercased_for_writes(self) -> None:
        status, resp = self.respond(
            {"operation": WRITE_REGISTER, "payload": ascii_hex("EAF")}
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "error", "code": "af"})

    def test_read_memory_ok(self) -> None:
        status, resp = self.respond(
            {"operation": READ_MEMORY, "payload": ascii_hex("cafe"), "expected_length": 2}
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "ok", "data": "cafe"})

    def test_read_register_ok_normalizes_case(self) -> None:
        status, resp = self.respond(
            {"operation": READ_REGISTER, "payload": ascii_hex("DEADBEEF"), "expected_size": 4}
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "ok", "value": "deadbeef"})

    def test_write_ok(self) -> None:
        for operation in (WRITE_MEMORY, WRITE_REGISTER):
            with self.subTest(operation=operation):
                status, resp = self.respond(
                    {"operation": operation, "payload": ascii_hex("OK")}
                )
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "ok"})

    def test_expected_length_and_size_limits(self) -> None:
        good_mem = {"operation": READ_MEMORY, "payload": ascii_hex("ab" * 4096),
                    "expected_length": 4096}
        status, _ = self.respond(good_mem)
        self.assertEqual(status, 200)
        good_reg = {"operation": READ_REGISTER, "payload": ascii_hex("ab" * 32),
                    "expected_size": 32}
        status, _ = self.respond(good_reg)
        self.assertEqual(status, 200)

        bad = [
            {"operation": READ_MEMORY, "payload": "", "expected_length": 0},
            {"operation": READ_MEMORY, "payload": "", "expected_length": 4097},
            {"operation": READ_MEMORY, "payload": "", "expected_length": True},
            {"operation": READ_REGISTER, "payload": "", "expected_size": 0},
            {"operation": READ_REGISTER, "payload": "", "expected_size": 33},
        ]
        for body in bad:
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_writes_must_not_carry_expected_length(self) -> None:
        for field in ("expected_length", "expected_size"):
            body = {"operation": WRITE_MEMORY, "payload": ascii_hex("OK"), field: 1}
            with self.subTest(field=field):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_reads_require_expectation(self) -> None:
        for body in (
            {"operation": READ_MEMORY, "payload": ascii_hex("ab")},
            {"operation": READ_REGISTER, "payload": ascii_hex("ab")},
        ):
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_missing_and_unknown_fields(self) -> None:
        for body in (
            {},
            {"payload": ascii_hex("ab"), "expected_length": 1},
            {"operation": "read_io", "payload": "", "expected_length": 1},
            {"operation": 5, "payload": ""},
            {"operation": WRITE_MEMORY, "payload": ascii_hex("OK"), "extra": 1},
        ):
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_outer_payload_hex_errors_are_invalid_field(self) -> None:
        for payload in ("abc", "zz", "0x4f"):
            body = {"operation": WRITE_MEMORY, "payload": payload}
            with self.subTest(payload=payload):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_invalid_responses(self) -> None:
        cases = [
            # OK is not a read reply, hex data is not a write reply.
            {"operation": READ_MEMORY, "payload": ascii_hex("OK"), "expected_length": 2},
            {"operation": READ_REGISTER, "payload": ascii_hex("OK"), "expected_size": 2},
            {"operation": WRITE_MEMORY, "payload": ascii_hex("abcd")},
            {"operation": WRITE_REGISTER, "payload": ascii_hex("ab")},
            # Malformed E replies (truncated, non-hex code, extra byte).
            {"operation": READ_MEMORY, "payload": ascii_hex("E0"), "expected_length": 1},
            {"operation": READ_MEMORY, "payload": ascii_hex("Ezz"), "expected_length": 1},
            {"operation": READ_MEMORY, "payload": ascii_hex("E012"), "expected_length": 2},
            # Read data: odd length, non-hex, length mismatch, trailing junk.
            {"operation": READ_MEMORY, "payload": ascii_hex("abc"), "expected_length": 2},
            {"operation": READ_MEMORY, "payload": ascii_hex("zz"), "expected_length": 1},
            {"operation": READ_MEMORY, "payload": ascii_hex("ab"), "expected_length": 2},
            {"operation": READ_MEMORY, "payload": ascii_hex("abcd"), "expected_length": 3},
            {"operation": READ_REGISTER, "payload": ascii_hex("ab!"), "expected_size": 1},
            # Writes only accept exact uppercase ASCII OK.
            {"operation": WRITE_MEMORY, "payload": ascii_hex("ok")},
            {"operation": WRITE_MEMORY, "payload": ascii_hex("OK!")},
            {"operation": WRITE_MEMORY, "payload": ascii_hex(" OK")},
            # Non-ASCII payload bytes.
            {"operation": READ_MEMORY, "payload": "ff", "expected_length": 1},
            {"operation": WRITE_MEMORY, "payload": "80"},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_response")

    def test_not_json_object(self) -> None:
        for raw in (b"not json", b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(RESPONSE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")


class DecodeFlashResponseTest(RspCommandsHttpTest):
    def test_empty_payload_is_unsupported(self) -> None:
        for operation in (FLASH_ERASE, FLASH_WRITE, FLASH_DONE):
            with self.subTest(operation=operation):
                status, resp = self.respond({"operation": operation, "payload": ""})
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "unsupported"})

    def test_ok(self) -> None:
        for operation in (FLASH_ERASE, FLASH_WRITE, FLASH_DONE):
            with self.subTest(operation=operation):
                status, resp = self.respond(
                    {"operation": operation, "payload": ascii_hex("OK")}
                )
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "ok"})

    def test_error_code_lowercased(self) -> None:
        for operation, reply in (
            (FLASH_ERASE, "E01"),
            (FLASH_WRITE, "EAF"),
            (FLASH_DONE, "Eff"),
        ):
            with self.subTest(operation=operation):
                status, resp = self.respond(
                    {"operation": operation, "payload": ascii_hex(reply)}
                )
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "error", "code": reply[1:].lower()})

    def test_invalid_responses(self) -> None:
        cases = [
            # Any non-OK data reply is rejected.
            ascii_hex("abcd"),
            # Malformed E replies: truncated, non-hex code, extra byte.
            ascii_hex("E0"),
            ascii_hex("Ezz"),
            ascii_hex("E012"),
            # Exact uppercase ASCII OK only.
            ascii_hex("ok"),
            ascii_hex("OK!"),
            ascii_hex(" OK"),
            # Non-ASCII payload bytes.
            "80",
            "4f80",
        ]
        for operation in (FLASH_ERASE, FLASH_WRITE, FLASH_DONE):
            for payload in cases:
                with self.subTest(operation=operation, payload=payload):
                    status, resp = self.respond(
                        {"operation": operation, "payload": payload}
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(resp["error"]["code"], "invalid_response")

    def test_fields_only_operation_and_payload(self) -> None:
        good = {"operation": FLASH_WRITE, "payload": ascii_hex("OK")}
        status, _ = self.respond(good)
        self.assertEqual(status, 200)
        for body in (
            {},
            {"payload": ascii_hex("OK")},
            {"operation": FLASH_ERASE},
            {"operation": FLASH_DONE, "payload": "", "expected_length": 1},
            {"operation": FLASH_WRITE, "payload": ascii_hex("OK"), "expected_size": 1},
            {"operation": FLASH_DONE, "payload": "", "address": 0},
            {"operation": FLASH_DONE, "payload": "", "data": "ab"},
            {"operation": FLASH_DONE, "payload": "", "extra": 1},
            {"operation": "flash_reset", "payload": ""},
            {"operation": 9, "payload": ""},
        ):
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_outer_payload_hex_errors_are_invalid_field(self) -> None:
        for payload in ("abc", "zz", "0x4f"):
            for operation in (FLASH_ERASE, FLASH_WRITE, FLASH_DONE):
                with self.subTest(operation=operation, payload=payload):
                    status, resp = self.respond(
                        {"operation": operation, "payload": payload}
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_not_json_object(self) -> None:
        for raw in (b"not json", b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(RESPONSE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")


class DecodeExecutionResponseTest(RspCommandsHttpTest):
    def exec_respond(self, text: str, operation: str = CONTINUE) -> tuple[int, dict]:
        return self.respond({"operation": operation, "payload": ascii_hex(text)})

    def test_empty_payload_is_unsupported(self) -> None:
        for operation in (CONTINUE, SINGLE_STEP):
            with self.subTest(operation=operation):
                status, resp = self.respond({"operation": operation, "payload": ""})
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "unsupported"})

    def test_error_code(self) -> None:
        status, resp = self.exec_respond("EAF")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "error", "code": "af"})

    def test_signal_stop(self) -> None:
        status, resp = self.exec_respond("S05")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "stopped", "signal": "05", "details": []})

    def test_signal_stop_signal_lowercased(self) -> None:
        status, resp = self.exec_respond("SAB")
        self.assertEqual(status, 200)
        self.assertEqual(resp["signal"], "ab")
        self.assertEqual(resp["details"], [])

    def test_t_stop_with_fields_in_order(self) -> None:
        status, resp = self.exec_respond("T0505:04;thread:000f;")
        self.assertEqual(status, 200)
        self.assertEqual(
            resp,
            {
                "status": "stopped",
                "signal": "05",
                "details": [
                    {"key": "05", "value": "04"},
                    {"key": "thread", "value": "000f"},
                ],
            },
        )

    def test_t_stop_without_trailing_semicolon(self) -> None:
        status, resp = self.exec_respond("T0b00:deadbeef")
        self.assertEqual(status, 200)
        self.assertEqual(resp["signal"], "0b")
        self.assertEqual(resp["details"], [{"key": "00", "value": "deadbeef"}])

    def test_t_stop_no_fields(self) -> None:
        status, resp = self.exec_respond("T01")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "stopped", "signal": "01", "details": []})

    def test_t_stop_signal_lowercased(self) -> None:
        status, resp = self.exec_respond("TAF05:04")
        self.assertEqual(status, 200)
        self.assertEqual(resp["signal"], "af")

    def test_t_stop_preserves_duplicate_keys(self) -> None:
        status, resp = self.exec_respond("T05k:1;k:2;")
        self.assertEqual(status, 200)
        self.assertEqual(
            resp["details"],
            [{"key": "k", "value": "1"}, {"key": "k", "value": "2"}],
        )

    def test_w_exited(self) -> None:
        status, resp = self.exec_respond("W00")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "exited", "code": "00"})

    def test_w_exited_lowercased(self) -> None:
        status, resp = self.exec_respond("WAB")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "exited", "code": "ab"})

    def test_x_terminated(self) -> None:
        status, resp = self.exec_respond("X09", SINGLE_STEP)
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "terminated", "signal": "09"})

    def test_console_data(self) -> None:
        status, resp = self.exec_respond("O48656c6c6f")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "console", "data": "48656c6c6f"})

    def test_console_empty_data(self) -> None:
        status, resp = self.exec_respond("O")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "console", "data": ""})

    def test_console_data_lowercased(self) -> None:
        status, resp = self.exec_respond("OABCD")
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "console", "data": "abcd"})

    def test_expected_fields_rejected(self) -> None:
        for field in ("expected_length", "expected_size"):
            body = {"operation": CONTINUE, "payload": "", field: 1}
            with self.subTest(field=field):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_missing_and_unknown_fields(self) -> None:
        for body in (
            {},
            {"payload": ascii_hex("S05")},
            {"operation": "step", "payload": ascii_hex("S05")},
            {"operation": 7, "payload": ascii_hex("S05")},
            {"operation": CONTINUE, "payload": ascii_hex("S05"), "extra": 1},
        ):
            with self.subTest(body=body):
                status, resp = self.respond(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_invalid_responses(self) -> None:
        cases = [
            # Unknown prefix / OK.
            "OK",
            "Q01",
            "Z05",
            # S: bad width / non-hex / extra.
            "S5",
            "S005",
            "Szz",
            "S050",
            # T: bad signal / field errors.
            "T5",
            "Tz05:04;",
            "T050504;",          # no colon
            "T05:04;",           # empty key
            "T0505:;",           # empty value
            "T0505",             # no colon (single token)
            "T05;05:04;",        # leading semicolon -> empty field
            "T0505:04;;06:07;",  # double semicolon
            "T0505:04;x",        # value-only token
            # W / X.
            "W0",
            "Wzz",
            "W001",
            "X0",
            "Xg0",
            # E.
            "E1",
            "Ezz",
            "E001",
            # O: odd length / non-hex.
            "Oabc",
            "Ozz",
            "O48g",
        ]
        for text in cases:
            with self.subTest(text=text):
                status, resp = self.exec_respond(text)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_response")

    def test_non_ascii_payload_is_invalid_response(self) -> None:
        # 0x80 after an S prefix is not ASCII.
        status, resp = self.respond({"operation": CONTINUE, "payload": "5380"})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_response")


if __name__ == "__main__":
    unittest.main()
