import json
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server

ENCODE_PATH = "/v1/rsp/commands/encode"
DECODE_PATH = "/v1/rsp/commands/decode-response"
PACKET_PATH = "/v1/rsp/encode"


class CommandsHttpTest(unittest.TestCase):
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

    def encode(self, body: dict) -> tuple[int, dict]:
        return self.post(ENCODE_PATH, json.dumps(body).encode("utf-8"))

    def decode(self, body: dict) -> tuple[int, dict]:
        return self.post(DECODE_PATH, json.dumps(body).encode("utf-8"))


class EncodeCommandTest(CommandsHttpTest):
    def assertPayload(self, body: dict, expected_ascii: str) -> None:
        status, resp = self.encode(body)
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"payload": expected_ascii.encode("ascii").hex()})

    def test_read_memory(self) -> None:
        self.assertPayload(
            {"operation": "read_memory", "address": 0x1A0, "length": 16},
            "m1a0,10",
        )

    def test_read_memory_zero_address(self) -> None:
        self.assertPayload({"operation": "read_memory", "address": 0, "length": 1}, "m0,1")

    def test_read_memory_max_range(self) -> None:
        self.assertPayload(
            {"operation": "read_memory", "address": 0xFFFFFFFF, "length": 1},
            "mffffffff,1",
        )
        self.assertPayload(
            {"operation": "read_memory", "address": 0xFFFFF000, "length": 4096},
            "mfffff000,1000",
        )

    def test_write_memory(self) -> None:
        self.assertPayload(
            {"operation": "write_memory", "address": 0x2000, "data": "deadBEef"},
            "M2000,4:deadbeef",
        )

    def test_read_register(self) -> None:
        self.assertPayload({"operation": "read_register", "register": 8}, "p8")
        self.assertPayload({"operation": "read_register", "register": 0xFFFF}, "pffff")

    def test_write_register(self) -> None:
        self.assertPayload(
            {"operation": "write_register", "register": 0x10, "value": "01020304"},
            "P10=01020304",
        )

    def test_payload_feeds_packet_encode(self) -> None:
        status, resp = self.encode({"operation": "read_memory", "address": 0, "length": 4})
        self.assertEqual(status, 200)
        status, packet = self.post(PACKET_PATH, json.dumps(resp).encode("utf-8"))
        self.assertEqual(status, 200)
        wire = b"$m0,4#" + f"{sum(b'm0,4') % 256:02x}".encode("ascii")
        self.assertEqual(packet, {"packet": wire.hex()})

    def test_not_json_object(self) -> None:
        status, resp = self.post(ENCODE_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for raw in (b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(ENCODE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_operation_errors(self) -> None:
        cases = [
            {},
            {"operation": None},
            {"operation": 5},
            {"operation": "read"},
            {"operation": "READ_MEMORY"},
            {"operation": ""},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_field_errors(self) -> None:
        cases = [
            {"operation": "read_memory", "address": 0},  # missing length
            {"operation": "read_memory", "address": 0, "length": 1, "data": "00"},  # extra
            {"operation": "read_memory", "address": "0", "length": 1},
            {"operation": "read_memory", "address": True, "length": 1},
            {"operation": "read_memory", "address": -1, "length": 1},
            {"operation": "read_memory", "address": 0x100000000, "length": 1},
            {"operation": "read_memory", "address": 0, "length": 0},
            {"operation": "read_memory", "address": 0, "length": 4097},
            {"operation": "read_memory", "address": 0, "length": 1.5},
            {"operation": "read_memory", "address": 0xFFFFFFFF, "length": 2},  # overflow
            {"operation": "write_memory", "address": 0, "data": ""},  # empty data
            {"operation": "write_memory", "address": 0, "data": "abc"},  # odd length
            {"operation": "write_memory", "address": 0, "data": "zz"},
            {"operation": "write_memory", "address": 0, "data": "0x00"},
            {"operation": "write_memory", "address": 0, "data": "00" * 4097},
            {"operation": "write_memory", "address": 0xFFFFFFFF, "data": "0000"},  # overflow
            {"operation": "write_memory", "address": 0, "data": 5},
            {"operation": "read_register", "register": 0x10000},
            {"operation": "read_register", "register": -1},
            {"operation": "read_register", "register": "8"},
            {"operation": "read_register", "register": 1, "value": "00"},  # extra
            {"operation": "write_register", "register": 0, "value": ""},
            {"operation": "write_register", "register": 0, "value": "00" * 33},
            {"operation": "write_register", "register": 0, "value": "0g"},
            {"operation": "write_register", "register": 0},  # missing value
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_boundary_sizes_accepted(self) -> None:
        status, _ = self.encode({"operation": "write_memory", "address": 0, "data": "00" * 4096})
        self.assertEqual(status, 200)
        status, _ = self.encode({"operation": "write_register", "register": 0, "value": "00" * 32})
        self.assertEqual(status, 200)


class DecodeResponseTest(CommandsHttpTest):
    def test_empty_payload_unsupported(self) -> None:
        for body in (
            {"operation": "read_memory", "payload": "", "expected_length": 4},
            {"operation": "write_memory", "payload": ""},
            {"operation": "read_register", "payload": "", "expected_size": 4},
            {"operation": "write_register", "payload": ""},
        ):
            with self.subTest(body=body):
                status, resp = self.decode(body)
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "unsupported"})

    def test_error_reply(self) -> None:
        for op_body in (
            {"operation": "read_memory", "expected_length": 4},
            {"operation": "write_memory"},
            {"operation": "read_register", "expected_size": 4},
            {"operation": "write_register"},
        ):
            with self.subTest(body=op_body):
                status, resp = self.decode({**op_body, "payload": b"E0a".hex()})
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "error", "code": "0a"})

    def test_error_reply_uppercase_normalized(self) -> None:
        status, resp = self.decode({"operation": "write_memory", "payload": b"EAF".hex()})
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "error", "code": "af"})

    def test_read_memory_ok(self) -> None:
        status, resp = self.decode(
            {"operation": "read_memory", "payload": b"DEADbeef".hex(), "expected_length": 4}
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "ok", "data": "deadbeef"})

    def test_read_register_ok(self) -> None:
        status, resp = self.decode(
            {"operation": "read_register", "payload": b"01020304".hex(), "expected_size": 4}
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"status": "ok", "value": "01020304"})

    def test_write_ok(self) -> None:
        for op in ("write_memory", "write_register"):
            with self.subTest(op=op):
                status, resp = self.decode({"operation": op, "payload": b"OK".hex()})
                self.assertEqual(status, 200)
                self.assertEqual(resp, {"status": "ok"})

    def test_not_json_object(self) -> None:
        status, resp = self.post(DECODE_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for raw in (b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(DECODE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        cases = [
            {},
            {"operation": "read_memory"},  # missing payload and expected_length
            {"operation": "read_memory", "payload": ""},  # missing expected_length
            {"operation": "read_memory", "payload": "", "expected_length": 0},
            {"operation": "read_memory", "payload": "", "expected_length": 4097},
            {"operation": "read_memory", "payload": "", "expected_length": "4"},
            {"operation": "read_memory", "payload": "", "expected_length": True},
            {"operation": "read_memory", "payload": "", "expected_length": 4, "extra": 1},
            {"operation": "read_register", "payload": "", "expected_size": 0},
            {"operation": "read_register", "payload": "", "expected_size": 33},
            {"operation": "read_register", "payload": "", "expected_length": 4},  # wrong name
            {"operation": "write_memory", "payload": "", "expected_length": 4},  # not allowed
            {"operation": "write_register", "payload": "", "expected_size": 4},  # not allowed
            {"operation": "write_memory", "payload": "abc"},  # odd hex
            {"operation": "write_memory", "payload": "zz"},
            {"operation": "write_memory", "payload": 5},
            {"operation": "read_memory", "payload": None, "expected_length": 4},
            {"operation": "erase_flash", "payload": ""},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.decode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_invalid_response(self) -> None:
        cases = [
            # non-ASCII bytes in the reply
            {"operation": "read_memory", "payload": "00ff", "expected_length": 1},
            {"operation": "write_memory", "payload": "00"},
            # malformed error replies
            {"operation": "write_memory", "payload": b"E".hex()},  # truncated
            {"operation": "write_memory", "payload": b"E1".hex()},  # truncated
            {"operation": "write_memory", "payload": b"E123".hex()},  # too long
            {"operation": "write_memory", "payload": b"Exx".hex()},  # bad hex chars
            # write success form must be exactly OK
            {"operation": "write_memory", "payload": b"ok".hex()},
            {"operation": "write_memory", "payload": b"OK ".hex()},
            {"operation": "write_memory", "payload": b"O".hex()},
            {"operation": "write_register", "payload": "4f4b00"},
            {"operation": "write_memory", "payload": b"deadbeef".hex()},  # data, not OK
            # read length mismatch
            {"operation": "read_memory", "payload": b"deadbeef".hex(), "expected_length": 3},
            {"operation": "read_memory", "payload": b"dead".hex(), "expected_length": 4},
            {"operation": "read_register", "payload": b"0102030405".hex(), "expected_size": 4},
            # read reply with non-hex characters
            {"operation": "read_memory", "payload": b"OK".hex(), "expected_length": 1},
            {"operation": "read_register", "payload": b"zzzz".hex(), "expected_size": 2},
            # odd number of hex characters in read reply
            {"operation": "read_memory", "payload": b"abc".hex(), "expected_length": 1},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.decode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_response")


if __name__ == "__main__":
    unittest.main()
