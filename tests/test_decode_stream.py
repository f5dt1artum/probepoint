import json
import unittest
import urllib.error
import urllib.request
import zlib

from probepoint.frames import HEADER_LEN, MAX_PAYLOAD
from probepoint.server import make_server

PATH = "/v1/frames/decode-stream"


def build_frame(flags=0, sequence=0, opcode=0, payload=b"", version=1, length=None):
    import struct

    declared = len(payload) if length is None else length
    header = struct.pack(">HBBIHH", 0x5050, version, flags, sequence, opcode, declared)
    crc = zlib.crc32(header[2:] + payload)
    return header + payload + struct.pack(">I", crc)


class StreamHttpTest(unittest.TestCase):
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

    def stream(self, data: str, eof: bool) -> tuple[int, dict]:
        return self.post(PATH, json.dumps({"data": data, "eof": eof}).encode("utf-8"))

    def stream_raw(self, raw: bytes) -> tuple[int, dict]:
        return self.post(PATH, raw)


class DecodeStreamTest(StreamHttpTest):
    def frame(self, **kw) -> bytes:
        return build_frame(**kw)

    def test_empty_data(self) -> None:
        for eof in (False, True):
            with self.subTest(eof=eof):
                status, body = self.stream("", eof)
                self.assertEqual(status, 200)
                self.assertEqual(
                    body,
                    {"frames": [], "errors": [], "discarded": 0, "remainder": ""},
                )

    def test_single_frame_with_offset(self) -> None:
        frame = self.frame(flags=7, sequence=99, opcode=0x1234, payload=b"\xca\xfe")
        status, body = self.stream(frame.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(body["errors"], [])
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

    def test_frame_item_and_error_item_shapes(self) -> None:
        frame = self.frame()
        status, body = self.stream(frame.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            set(body["frames"][0]),
            {"offset", "version", "flags", "sequence", "opcode", "payload"},
        )

        bad = bytearray(self.frame(version=2))
        status, body = self.stream(bytes(bad).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(set(body["errors"][0]), {"offset", "code"})

    def test_noise_before_frame_is_discarded(self) -> None:
        frame = self.frame(sequence=5)
        blob = b"\xaa\xbb" + frame
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["frames"][0]["offset"], 2)
        self.assertEqual(body["frames"][0]["sequence"], 5)

    def test_multiple_frames_in_order_with_duplicate_sequences(self) -> None:
        f1 = self.frame(sequence=1, opcode=1)
        f2 = self.frame(sequence=1, opcode=2)
        f3 = self.frame(sequence=1, opcode=3)
        status, body = self.stream((f1 + f2 + f3).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual([f["opcode"] for f in body["frames"]], [1, 2, 3])
        self.assertEqual([f["offset"] for f in body["frames"]], [0, len(f1), 2 * len(f1)])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["errors"], [])

    def test_uppercase_hex_accepted_remainder_lowercase(self) -> None:
        frame = self.frame()
        status, body = self.stream(frame.hex().upper(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["frames"]), 1)

        partial = frame[: HEADER_LEN + 1]
        status, body = self.stream(partial.hex().upper(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], partial.hex())
        self.assertEqual(body["frames"], [])

    def test_partial_candidate_waits_then_completes_on_resubmit(self) -> None:
        frame = self.frame(flags=9, sequence=42, opcode=7, payload=b"abc")
        split = HEADER_LEN + 1
        head, tail = frame[:split], frame[split:]

        status, body = self.stream(head.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"frames": [], "errors": [], "discarded": 0, "remainder": head.hex()})

        # Stateless: caller concatenates the remainder with the new fragment.
        status, body = self.stream((head + tail).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(body["frames"][0]["offset"], 0)
        self.assertEqual(body["frames"][0]["payload"], "616263")

    def test_noise_then_partial_noise_discarded_remainder_from_magic(self) -> None:
        frame = self.frame()
        partial = frame[:-2]
        status, body = self.stream((b"\xaa\xbb" + partial).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], partial.hex())

    def test_lone_0x50_kept_then_completes(self) -> None:
        frame = self.frame(opcode=0x0102)
        status, body = self.stream("50", False)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"frames": [], "errors": [], "discarded": 0, "remainder": "50"})

        status, body = self.stream(frame.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["frames"][0]["opcode"], 0x0102)

    def test_lone_0x50_with_eof_is_truncated(self) -> None:
        status, body = self.stream("0050", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["frames"], [])
        self.assertEqual(body["errors"], [{"offset": 1, "code": "truncated_frame"}])
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], "")

    def test_truncated_at_eof_reports_error(self) -> None:
        frame = self.frame()
        for partial in (frame[:1], frame[: HEADER_LEN - 1], frame[:-1]):
            with self.subTest(cut=len(partial)):
                status, body = self.stream(partial.hex(), True)
                self.assertEqual(status, 200)
                self.assertEqual(body["frames"], [])
                self.assertEqual(body["errors"], [{"offset": 0, "code": "truncated_frame"}])
                self.assertEqual(body["discarded"], len(partial))
                self.assertEqual(body["remainder"], "")

    def test_frame_then_truncated_tail_at_eof(self) -> None:
        frame = self.frame(opcode=10)
        tail = self.frame(opcode=11)[:5]
        status, body = self.stream((frame + tail).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual([f["opcode"] for f in body["frames"]], [10])
        self.assertEqual(body["errors"], [{"offset": len(frame), "code": "truncated_frame"}])
        self.assertEqual(body["discarded"], len(tail))
        self.assertEqual(body["remainder"], "")

    def test_unsupported_version_resyncs_and_finds_later_frame(self) -> None:
        bad = self.frame(version=2)  # 12-byte header with a bad version byte
        good = self.frame(opcode=0xABCD)
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_version"}])
        self.assertEqual(len(body["frames"]), 1)
        self.assertEqual(body["frames"][0]["offset"], len(bad))
        self.assertEqual(body["frames"][0]["opcode"], 0xABCD)
        # Every skipped byte of the bad candidate is discarded; the scan
        # only happens to find no inner magic in this crafted frame.
        self.assertEqual(body["discarded"], len(bad))

    def test_overlapping_magic_resync(self) -> None:
        # 50 50 50 | 01 ...: the bad candidate at 0 resyncs at offset 1 and
        # immediately finds a valid overlapping magic.
        good = self.frame(opcode=3)
        blob = b"\x50" + good
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_version"}])
        self.assertEqual(body["frames"][0]["offset"], 1)
        self.assertEqual(body["discarded"], 1)

    def test_invalid_length_resyncs(self) -> None:
        bad = self.frame(length=MAX_PAYLOAD + 1)
        good = self.frame(opcode=4)
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_length"}])
        self.assertEqual(body["frames"][0]["offset"], len(bad))
        self.assertEqual(body["discarded"], len(bad))

    def test_checksum_mismatch_resyncs_and_finds_later_frame(self) -> None:
        bad = bytearray(self.frame(opcode=5))
        bad[-1] ^= 0xFF
        good = self.frame(opcode=6)
        status, body = self.stream((bytes(bad) + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "checksum_mismatch"}])
        self.assertEqual([f["opcode"] for f in body["frames"]], [6])
        self.assertEqual(body["frames"][0]["offset"], len(bad))
        self.assertEqual(body["discarded"], len(bad))

    def test_errors_sorted_by_offset_mixed_with_frames(self) -> None:
        bad_version = self.frame(version=2)
        good1 = self.frame(opcode=1)
        bad_crc = bytearray(self.frame())
        bad_crc[-1] ^= 0xFF
        good2 = self.frame(opcode=2)
        blob = bad_version + good1 + bytes(bad_crc) + good2
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        offsets = [e["offset"] for e in body["errors"]]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(
            [(e["offset"], e["code"]) for e in body["errors"]],
            [
                (0, "unsupported_version"),
                (len(bad_version) + len(good1), "checksum_mismatch"),
            ],
        )
        self.assertEqual([f["opcode"] for f in body["frames"]], [1, 2])

    def test_bad_version_complete_header_reports_even_without_payload(self) -> None:
        # Once the header is complete the version is knowable; the missing
        # declared payload never gets a chance to matter.
        bad = self.frame(version=2, payload=b"")[:HEADER_LEN]
        status, body = self.stream(bad.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_version"}])
        self.assertEqual(body["discarded"], len(bad))

    def test_bad_version_complete_header_reports_with_eof_false(self) -> None:
        bad = self.frame(version=2, payload=b"")[:HEADER_LEN]
        status, body = self.stream(bad.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_version"}])
        self.assertEqual(body["discarded"], len(bad))
        self.assertEqual(body["remainder"], "")

    def test_incomplete_header_does_not_judge_version(self) -> None:
        # Fewer than 12 bytes: the version byte is present but the header
        # candidate cannot be evaluated yet, so it stays in the remainder.
        bad = self.frame(version=2)[: HEADER_LEN - 1]
        status, body = self.stream(bad.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["remainder"], bad.hex())
        self.assertEqual(body["discarded"], 0)

    def test_size_limit(self) -> None:
        status, body = self.stream("00" * (MAX_PAYLOAD * 256), True)  # exactly 1 MiB
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], MAX_PAYLOAD * 256)

        status, resp = self.stream("00" * (MAX_PAYLOAD * 256 + 1), True)
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")


class DecodeStreamValidationTest(StreamHttpTest):
    def test_not_json_object(self) -> None:
        status, resp = self.stream_raw(b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for raw in (b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.stream_raw(raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        good = {"data": "", "eof": False}
        cases = [
            {},
            {"data": ""},
            {"eof": False},
            {**good, "extra": 1},
            {"data": None, "eof": False},
            {"data": 5, "eof": False},
            {"data": [], "eof": False},
            {"data": "abc", "eof": False},  # odd length
            {"data": "0x50", "eof": False},  # prefix
            {"data": "50 50", "eof": False},  # separator
            {"data": "zz", "eof": False},
            {"data": "", "eof": 0},
            {"data": "", "eof": "false"},
            {"data": "", "eof": None},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post(PATH, json.dumps(body).encode("utf-8"))
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")


if __name__ == "__main__":
    unittest.main()
