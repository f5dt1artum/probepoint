import json
import unittest
import urllib.error
import urllib.request

from probepoint.frames import MAX_PAYLOAD
from probepoint.server import make_server


class FrameHttpTest(unittest.TestCase):
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

    def post_json(self, path: str, body: object) -> tuple[int, dict]:
        return self.post(path, json.dumps(body).encode("utf-8"))

    def encode(self, **fields: object) -> tuple[int, dict]:
        return self.post_json("/v1/frames/encode", fields)

    def decode(self, frame: str) -> tuple[int, dict]:
        return self.post_json("/v1/frames/decode", {"frame": frame})


class EncodeTest(FrameHttpTest):
    def test_encode_empty_payload(self) -> None:
        status, body = self.encode(flags=0, sequence=0, opcode=0, payload="")
        self.assertEqual(status, 200)
        self.assertEqual(list(body), ["frame"])
        frame = body["frame"]
        self.assertTrue(frame.startswith("50500100"))
        self.assertEqual(len(frame), 32)  # 16 bytes, no payload

    def test_encode_layout_and_roundtrip(self) -> None:
        status, body = self.encode(flags=0xA5, sequence=0x01020304, opcode=0xBEEF, payload="00ff10")
        self.assertEqual(status, 200)
        frame = body["frame"]
        self.assertEqual(frame, frame.lower())
        self.assertEqual(frame[:24], "505001a501020304beef0003")
        self.assertEqual(frame[24:30], "00ff10")

        status, decoded = self.decode(frame)
        self.assertEqual(status, 200)
        self.assertEqual(
            decoded,
            {"version": 1, "flags": 0xA5, "sequence": 0x01020304, "opcode": 0xBEEF, "payload": "00ff10"},
        )

    def test_encode_max_payload(self) -> None:
        payload = "ab" * MAX_PAYLOAD
        status, body = self.encode(flags=1, sequence=2, opcode=3, payload=payload)
        self.assertEqual(status, 200)
        status, decoded = self.decode(body["frame"])
        self.assertEqual(status, 200)
        self.assertEqual(decoded["payload"], payload)

    def test_encode_uppercase_payload_accepted(self) -> None:
        status, body = self.encode(flags=0, sequence=0, opcode=0, payload="AABB")
        self.assertEqual(status, 200)
        status, decoded = self.decode(body["frame"])
        self.assertEqual(decoded["payload"], "aabb")

    def test_encode_field_errors(self) -> None:
        good = {"flags": 1, "sequence": 2, "opcode": 3, "payload": ""}
        cases = [
            {},  # missing everything
            {**good, "extra": 1},  # unexpected field
            {**good, "flags": -1},
            {**good, "flags": 256},
            {**good, "flags": 1.5},
            {**good, "flags": True},
            {**good, "flags": "1"},
            {**good, "sequence": -1},
            {**good, "sequence": 1 << 32},
            {**good, "opcode": 1 << 16},
            {**good, "payload": "abc"},  # odd length
            {**good, "payload": "0x00"},  # prefix
            {**good, "payload": "00 ff"},  # separator
            {**good, "payload": "zz"},
            {**good, "payload": 12},
            {**good, "payload": "aa" * (MAX_PAYLOAD + 1)},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post_json("/v1/frames/encode", body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_encode_request_errors(self) -> None:
        status, resp = self.post("/v1/frames/encode", b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")

        for body in ([1, 2], "text", 42, None):
            with self.subTest(body=body):
                status, resp = self.post_json("/v1/frames/encode", body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")


class DecodeTest(FrameHttpTest):
    def good_frame(self) -> str:
        status, body = self.encode(flags=7, sequence=99, opcode=0x1234, payload="cafe")
        self.assertEqual(status, 200)
        return body["frame"]

    def test_decode_success(self) -> None:
        status, body = self.decode(self.good_frame())
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"version": 1, "flags": 7, "sequence": 99, "opcode": 0x1234, "payload": "cafe"},
        )

    def test_decode_field_errors(self) -> None:
        for body in ({}, {"frame": "zz"}, {"frame": "abc"}, {"frame": 5}, {"frame": "", "x": 1}):
            with self.subTest(body=body):
                status, resp = self.post_json("/v1/frames/decode", body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def expect_failure(self, frame: str, code: str) -> None:
        status, resp = self.decode(frame)
        self.assertEqual(status, 400, frame)
        self.assertEqual(resp["error"]["code"], code, frame)

    def test_truncated_below_minimum(self) -> None:
        self.expect_failure("5050", "truncated_frame")
        self.expect_failure("", "truncated_frame")

    def test_bad_magic(self) -> None:
        frame = "5151" + self.good_frame()[4:]
        self.expect_failure(frame, "bad_magic")

    def test_unsupported_version(self) -> None:
        frame = self.good_frame()
        frame = frame[:4] + "02" + frame[6:]
        self.expect_failure(frame, "unsupported_version")

    def test_invalid_length(self) -> None:
        frame = self.good_frame()
        frame = frame[:20] + "1001" + frame[24:]  # declared length 4097
        self.expect_failure(frame, "invalid_length")

    def test_truncated_declared(self) -> None:
        frame = self.good_frame()
        self.expect_failure(frame[:-2], "truncated_frame")

    def test_trailing_data(self) -> None:
        self.expect_failure(self.good_frame() + "00", "trailing_data")

    def test_checksum_mismatch(self) -> None:
        frame = self.good_frame()
        last = "0" if frame[-1] != "0" else "1"
        self.expect_failure(frame[:-1] + last, "checksum_mismatch")

    def test_failure_priority(self) -> None:
        # Short frame with bad magic reports truncation first.
        self.expect_failure("5151", "truncated_frame")
        # Bad magic with bad version reports magic first.
        frame = "5151" + "02" + self.good_frame()[6:]
        self.expect_failure(frame, "bad_magic")
        # Oversized declared length with trailing bytes reports invalid_length.
        frame = self.good_frame()
        frame = frame[:20] + "ffff" + frame[24:] + "00"
        self.expect_failure(frame, "invalid_length")


class RouteTest(FrameHttpTest):
    def test_healthz_unchanged(self) -> None:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz") as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read())
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "probepoint")

    def test_unknown_paths_404(self) -> None:
        for path in ("/nope", "/v1/frames"):
            with self.subTest(path=path):
                status, body = self.post_json(path, {})
                self.assertEqual(status, 404)
                self.assertEqual(body["error"]["code"], "not_found")
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/frames/encode", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()


if __name__ == "__main__":
    unittest.main()
