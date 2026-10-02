import json
import threading
import unittest
import urllib.error
import urllib.request

from probepoint.frames import encode_frame
from probepoint.server import make_server
from probepoint.stream import MAX_STREAM_DATA

PATH = "/v1/frames/decode-stream"


def make_frame(flags: int = 0, sequence: int = 0, opcode: int = 0, payload: str = "") -> str:
    return encode_frame(
        {"flags": flags, "sequence": sequence, "opcode": opcode, "payload": payload}
    )["frame"]


class DecodeStreamHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def post(self, raw: bytes) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{PATH}",
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

    def post_json(self, body: object) -> tuple[int, dict]:
        return self.post(json.dumps(body).encode("utf-8"))

    def scan(self, data: str, eof: bool) -> dict:
        status, body = self.post_json({"data": data, "eof": eof})
        self.assertEqual(status, 200, body)
        self.assertEqual(set(body), {"frames", "errors", "discarded", "remainder"})
        return body


class EmptyAndValidationTest(DecodeStreamHttpTest):
    def test_empty_data(self) -> None:
        for eof in (False, True):
            with self.subTest(eof=eof):
                body = self.scan("", eof)
                self.assertEqual(body["frames"], [])
                self.assertEqual(body["errors"], [])
                self.assertEqual(body["discarded"], 0)
                self.assertEqual(body["remainder"], "")

    def test_request_errors(self) -> None:
        status, resp = self.post(b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")

        for body in ([1, 2], "text", 42, None, True):
            with self.subTest(body=body):
                status, resp = self.post_json(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        cases = [
            {},  # missing everything
            {"data": ""},  # missing eof
            {"eof": True},  # missing data
            {"data": "", "eof": True, "x": 1},  # unexpected field
            {"data": 5, "eof": True},
            {"data": True, "eof": True},
            {"data": None, "eof": True},
            {"data": "abc", "eof": True},  # odd length
            {"data": "0x00", "eof": True},  # prefix
            {"data": "aa bb", "eof": True},  # separator
            {"data": "zz", "eof": True},
            {"data": "", "eof": 1},
            {"data": "", "eof": 0},
            {"data": "", "eof": "true"},
            {"data": "", "eof": None},
            {"data": "00" * (MAX_STREAM_DATA + 1), "eof": True},  # over limit
        ]
        for body in cases:
            with self.subTest(body=str(body)[:80]):
                status, resp = self.post_json(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_max_size_accepted(self) -> None:
        body = self.scan("00" * MAX_STREAM_DATA, True)
        self.assertEqual(body["frames"], [])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], MAX_STREAM_DATA)
        self.assertEqual(body["remainder"], "")


class ScanTest(DecodeStreamHttpTest):
    def test_single_frame(self) -> None:
        frame = make_frame(flags=7, sequence=99, opcode=0x1234, payload="cafe")
        body = self.scan(frame, True)
        self.assertEqual(
            body["frames"],
            [
                {
                    "offset": 0,
                    "version": 1,
                    "flags": 7,
                    "sequence": 99,
                    "opcode": 0x1234,
                    "payload": "cafe",
                }
            ],
        )
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")

    def test_noise_and_multiple_frames(self) -> None:
        f1 = make_frame(flags=1, sequence=1, opcode=1, payload="aa")
        f2 = make_frame(flags=2, sequence=2, opcode=2, payload="bbcc")
        n1 = len(f1) // 2
        body = self.scan("aabb" + f1 + "00" + f2, True)
        self.assertEqual([f["offset"] for f in body["frames"]], [2, 2 + n1 + 1])
        self.assertEqual([f["sequence"] for f in body["frames"]], [1, 2])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "")

    def test_duplicate_frames_kept_in_order(self) -> None:
        frame = make_frame(flags=3, sequence=42, opcode=8, payload="00")
        n = len(frame) // 2
        body = self.scan(frame + frame, True)
        self.assertEqual([f["offset"] for f in body["frames"]], [0, n])
        self.assertEqual([f["sequence"] for f in body["frames"]], [42, 42])
        self.assertEqual(body["discarded"], 0)

    def test_uppercase_data_accepted(self) -> None:
        frame = make_frame(flags=1, sequence=2, opcode=3, payload="aabb")
        body = self.scan(frame.upper(), True)
        self.assertEqual(len(body["frames"]), 1)
        self.assertEqual(body["frames"][0]["payload"], "aabb")

    def test_remainder_is_lowercase(self) -> None:
        frame = make_frame(flags=0xAB, sequence=0, opcode=0, payload="")
        head = frame[:8].upper()  # "505001AB"
        body = self.scan(head, False)
        self.assertEqual(body["remainder"], frame[:8])

    def test_noise_only(self) -> None:
        body = self.scan("aabbcc", True)
        self.assertEqual(body["frames"], [])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "")


class RemainderTest(DecodeStreamHttpTest):
    def test_partial_frame_held_for_every_cut(self) -> None:
        frame = make_frame(flags=3, sequence=7, opcode=9, payload="deadbeef")
        total = len(frame) // 2
        for cut in (1, 2, 5, 11, 12, 16, total - 1):
            with self.subTest(cut=cut):
                head = frame[: cut * 2]
                body = self.scan(head, False)
                self.assertEqual(body["frames"], [])
                self.assertEqual(body["errors"], [])
                self.assertEqual(body["discarded"], 0)
                self.assertEqual(body["remainder"], head)

                # Stateless: the caller re-submits remainder + new bytes.
                rejoined = self.scan(body["remainder"] + frame[cut * 2 :], True)
                self.assertEqual([f["offset"] for f in rejoined["frames"]], [0])
                self.assertEqual(rejoined["frames"][0]["sequence"], 7)
                self.assertEqual(rejoined["errors"], [])
                self.assertEqual(rejoined["discarded"], 0)
                self.assertEqual(rejoined["remainder"], "")

    def test_noise_before_partial_frame(self) -> None:
        frame = make_frame(flags=1, sequence=1, opcode=1, payload="aa")
        head = frame[:14]  # 7 bytes, header incomplete
        body = self.scan("ffee" + head, False)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], head)

    def test_trailing_lone_magic_byte(self) -> None:
        body = self.scan("aabb50", False)
        self.assertEqual(body["frames"], [])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], "50")

        body = self.scan("aabb50", True)
        self.assertEqual(body["frames"], [])
        self.assertEqual(body["errors"], [{"offset": 2, "code": "truncated_frame"}])
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "")

    def test_frame_then_partial_tail(self) -> None:
        frame = make_frame(flags=1, sequence=1, opcode=1, payload="")
        n = len(frame) // 2
        body = self.scan(frame + "5050", False)
        self.assertEqual([f["offset"] for f in body["frames"]], [0])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "5050")

        body = self.scan(frame + "5050", True)
        self.assertEqual([f["offset"] for f in body["frames"]], [0])
        self.assertEqual(body["errors"], [{"offset": n, "code": "truncated_frame"}])
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], "")

    def test_truncated_frame_eof(self) -> None:
        frame = make_frame(flags=1, sequence=1, opcode=1, payload="aabb")
        total = len(frame) // 2
        for cut in (2, 11, 12, 15, total - 1):
            with self.subTest(cut=cut):
                body = self.scan(frame[: cut * 2], True)
                self.assertEqual(body["frames"], [])
                self.assertEqual(body["errors"], [{"offset": 0, "code": "truncated_frame"}])
                self.assertEqual(body["discarded"], cut)
                self.assertEqual(body["remainder"], "")


class ResyncTest(DecodeStreamHttpTest):
    def test_unsupported_version_resync(self) -> None:
        good = make_frame(flags=1, sequence=5, opcode=6, payload="cafe")
        bad = good[:4] + "02" + good[6:]
        n = len(good) // 2
        body = self.scan(bad + good, True)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_version"}])
        self.assertEqual([f["offset"] for f in body["frames"]], [n])
        self.assertEqual(body["frames"][0]["sequence"], 5)
        self.assertEqual(body["discarded"], n)
        self.assertEqual(body["remainder"], "")

    def test_invalid_length_resync(self) -> None:
        header = "5050" + "01" + "00" + "00000000" + "0000" + "1001"  # declared 4097
        good = make_frame(flags=9, sequence=9, opcode=9, payload="")
        body = self.scan(header + good, True)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_length"}])
        self.assertEqual([f["offset"] for f in body["frames"]], [12])
        self.assertEqual(body["discarded"], 12)

    def test_checksum_mismatch_resync(self) -> None:
        good = make_frame(flags=1, sequence=5, opcode=6, payload="cafe")
        last = "0" if good[-1] != "0" else "1"
        bad = good[:-1] + last
        n = len(good) // 2
        body = self.scan(bad + good, True)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "checksum_mismatch"}])
        self.assertEqual([f["offset"] for f in body["frames"]], [n])
        self.assertEqual(body["discarded"], n)

    def test_overlapping_magic_resync(self) -> None:
        good = make_frame(flags=1, sequence=2, opcode=3, payload="")
        # "5050" + good: candidates at 0 and 1 see version 0x50, the real
        # frame starts at offset 2.
        body = self.scan("5050" + good, True)
        self.assertEqual(
            body["errors"],
            [
                {"offset": 0, "code": "unsupported_version"},
                {"offset": 1, "code": "unsupported_version"},
            ],
        )
        self.assertEqual([f["offset"] for f in body["frames"]], [2])
        self.assertEqual(body["discarded"], 2)

    def test_multiple_errors_sorted_by_offset(self) -> None:
        good = make_frame(flags=1, sequence=1, opcode=1, payload="")
        bad_version = good[:4] + "03" + good[6:]
        bad_length = "5050" + "01" + "00" + "00000000" + "0000" + "ffff"
        n = len(good) // 2
        body = self.scan(bad_version + bad_length + good, True)
        self.assertEqual(
            body["errors"],
            [
                {"offset": 0, "code": "unsupported_version"},
                {"offset": n, "code": "invalid_length"},
            ],
        )
        self.assertEqual([f["offset"] for f in body["frames"]], [n + 12])
        self.assertEqual(body["discarded"], n + 12)

    def test_error_entries_carry_only_offset_and_code(self) -> None:
        good = make_frame(flags=1, sequence=1, opcode=1, payload="")
        bad = good[:4] + "02" + good[6:]
        body = self.scan(bad, True)
        self.assertEqual(len(body["errors"]), 1)
        self.assertEqual(set(body["errors"][0]), {"offset", "code"})
        self.assertEqual(set(body["frames"][0]) if body["frames"] else set(), set())


if __name__ == "__main__":
    unittest.main()
