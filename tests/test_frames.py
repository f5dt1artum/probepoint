import json
import threading
import unittest
import urllib.error
import urllib.request
import zlib
from http.server import ThreadingHTTPServer

from probepoint.frames import FrameError, decode, encode
from probepoint.server import Handler
from probepoint.service import Service, ServiceError


class CodecRoundTripTest(unittest.TestCase):
    def test_empty_payload_round_trip(self) -> None:
        frame = encode(0x00, 0, 0x0000, b"")
        self.assertEqual(frame, bytes.fromhex("505001000000000000000000" + f"{zlib.crc32(frame[2:12]) & 0xFFFFFFFF:08x}"))
        decoded = decode(frame)
        self.assertEqual(decoded["version"], 1)
        self.assertEqual(decoded["flags"], 0)
        self.assertEqual(decoded["sequence"], 0)
        self.assertEqual(decoded["opcode"], 0)
        self.assertEqual(decoded["payload"], b"")

    def test_max_payload_round_trip(self) -> None:
        payload = bytes((i * 7 + 3) & 0xFF for i in range(4096))
        frame = encode(0xFF, 0xFFFFFFFF, 0xFFFF, payload)
        decoded = decode(frame)
        self.assertEqual(decoded["version"], 1)
        self.assertEqual(decoded["flags"], 0xFF)
        self.assertEqual(decoded["sequence"], 0xFFFFFFFF)
        self.assertEqual(decoded["opcode"], 0xFFFF)
        self.assertEqual(decoded["payload"], payload)

    def test_crc_covers_version_through_payload(self) -> None:
        frame = bytearray(encode(1, 2, 3, b"abc"))
        covered = bytes(frame[2:-4])
        self.assertEqual(int.from_bytes(frame[-4:], "big"), zlib.crc32(covered) & 0xFFFFFFFF)

    def test_decode_priority(self) -> None:
        good = encode(1, 2, 3, b"abc")

        cases = [
            ("truncated_frame", good[:15]),
            ("bad_magic", b"\x00\x00" + bytes(good[2:])),
            ("unsupported_version", bytes(good[:2]) + b"\x02" + bytes(good[3:])),
        ]
        for code, bad in cases:
            with self.subTest(code=code):
                with self.assertRaises(FrameError) as ctx:
                    decode(bad)
                self.assertEqual(ctx.exception.code, code)

    def test_invalid_declared_length(self) -> None:
        frame = bytearray(encode(0, 0, 0, b""))
        frame[10:12] = (4097).to_bytes(2, "big")
        with self.assertRaises(FrameError) as ctx:
            decode(bytes(frame))
        self.assertEqual(ctx.exception.code, "invalid_length")

    def test_truncated_and_trailing(self) -> None:
        frame = encode(0, 0, 0, b"abc")
        with self.assertRaises(FrameError) as ctx:
            decode(frame[:-1])
        self.assertEqual(ctx.exception.code, "truncated_frame")
        with self.assertRaises(FrameError) as ctx:
            decode(frame + b"\x00")
        self.assertEqual(ctx.exception.code, "trailing_data")

    def test_checksum_mismatch(self) -> None:
        frame = bytearray(encode(0, 0, 0, b"abc"))
        frame[-1] ^= 0xFF
        with self.assertRaises(FrameError) as ctx:
            decode(bytes(frame))
        self.assertEqual(ctx.exception.code, "checksum_mismatch")


class ServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = Service()

    def test_encode_output_is_lowercase_hex(self) -> None:
        result = self.service.encode_frame({"flags": 0xAB, "sequence": 1, "opcode": 2, "payload": "DEADbeef"})
        self.assertEqual(set(result), {"frame"})
        self.assertEqual(result["frame"], result["frame"].lower())
        self.assertEqual(result["frame"], encode(0xAB, 1, 2, bytes.fromhex("deadbeef")).hex())

    def test_decode_returns_lowercase_payload(self) -> None:
        frame = encode(5, 9, 10, bytes.fromhex("aAbB")).hex()
        result = self.service.decode_frame({"frame": frame.upper()})
        self.assertEqual(result, {"version": 1, "flags": 5, "sequence": 9, "opcode": 10, "payload": "aabb"})

    def test_field_errors(self) -> None:
        good = {"flags": 0, "sequence": 0, "opcode": 0, "payload": ""}
        bad_requests = [
            {},
            {"flags": 0, "sequence": 0, "opcode": 0},
            {**good, "extra": 1},
            {"flags": 256, "sequence": 0, "opcode": 0, "payload": ""},
            {"flags": -1, "sequence": 0, "opcode": 0, "payload": ""},
            {"flags": True, "sequence": 0, "opcode": 0, "payload": ""},
            {"flags": 1.0, "sequence": 0, "opcode": 0, "payload": ""},
            {"flags": 0, "sequence": 2**32, "opcode": 0, "payload": ""},
            {"flags": 0, "sequence": 0, "opcode": 65536, "payload": ""},
            {"flags": 0, "sequence": 0, "opcode": 0, "payload": "abc"},
            {"flags": 0, "sequence": 0, "opcode": 0, "payload": "xy"},
            {"flags": 0, "sequence": 0, "opcode": 0, "payload": 1},
            {"flags": 0, "sequence": 0, "opcode": 0, "payload": "00" * 4097},
        ]
        for request in bad_requests:
            with self.subTest(request=request):
                with self.assertRaises(ServiceError) as ctx:
                    self.service.encode_frame(request)
                self.assertEqual(ctx.exception.code, "invalid_field")

    def test_decode_field_errors(self) -> None:
        frame = encode(0, 0, 0, b"").hex()
        for request in ({}, {"frame": frame, "x": 1}, {"frame": "zz"}, {"frame": 1}):
            with self.subTest(request=request):
                with self.assertRaises(ServiceError) as ctx:
                    self.service.decode_frame(request)
                self.assertEqual(ctx.exception.code, "invalid_field")


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, method: str, path: str, body: bytes | None = None, raw: bool = False):
        req = urllib.request.Request(self.base + path, data=body, method=method)
        if body is not None and not raw:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def test_healthz_unchanged(self) -> None:
        status, body = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "probepoint")

    def test_encode_decode_over_http(self) -> None:
        status, body = self.request("POST", "/v1/frames/encode",
                                    json.dumps({"flags": 1, "sequence": 42, "opcode": 7, "payload": "cafe"}).encode())
        self.assertEqual(status, 200)
        frame_hex = body["frame"]
        status, body = self.request("POST", "/v1/frames/decode", json.dumps({"frame": frame_hex}).encode())
        self.assertEqual(status, 200)
        self.assertEqual(body, {"version": 1, "flags": 1, "sequence": 42, "opcode": 7, "payload": "cafe"})

    def test_invalid_json(self) -> None:
        for raw_body in (b"{not json", b"", b"[1,2]", b'"x"', b"123", b"null"):
            with self.subTest(raw_body=raw_body):
                status, body = self.request("POST", "/v1/frames/encode", raw_body, raw=True)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_request")

    def test_invalid_field_over_http(self) -> None:
        status, body = self.request("POST", "/v1/frames/encode", b'{"flags": 256}')
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_decode_failures_over_http(self) -> None:
        frame = encode(0, 0, 0, b"abc").hex()
        cases = {
            frame[:-2]: "truncated_frame",
        }
        for frame_hex, code in cases.items():
            status, body = self.request("POST", "/v1/frames/decode", json.dumps({"frame": frame_hex}).encode())
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], code)

    def test_unknown_path(self) -> None:
        status, body = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")
        status, body = self.request("POST", "/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
