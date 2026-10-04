import json
import unittest
import urllib.error
import urllib.request
import zlib

from probepoint.frames import HEADER_LEN, MAX_PAYLOAD
from probepoint.server import make_server

ENCODE_PATH = "/v1/channels/encode"
DECODE_PATH = "/v1/channels/decode-stream"


def build_frame(flags=0, sequence=0, opcode=0, payload=b"", version=1, length=None):
    import struct

    declared = len(payload) if length is None else length
    header = struct.pack(">HBBIHH", 0x5050, version, flags, sequence, opcode, declared)
    crc = zlib.crc32(header[2:] + payload)
    return header + payload + struct.pack(">I", crc)


class ChannelHttpTest(unittest.TestCase):
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

    def encode(self, channel: str, sequence: int, data: str) -> tuple[int, dict]:
        return self.post_json(ENCODE_PATH, {"channel": channel, "sequence": sequence, "data": data})

    def stream(self, data: str, eof: bool) -> tuple[int, dict]:
        return self.post_json(DECODE_PATH, {"data": data, "eof": eof})

    def stream_raw(self, raw: bytes) -> tuple[int, dict]:
        return self.post(DECODE_PATH, raw)


class EncodeChannelTest(ChannelHttpTest):
    def test_channel_opcodes_flags_zero_and_sequence_passthrough(self) -> None:
        cases = [
            ("debug", 0x0001),
            ("serial", 0x0002),
            ("log", 0x0003),
        ]
        for channel, opcode in cases:
            with self.subTest(channel=channel):
                status, body = self.encode(channel, 0x01020304, "cafe")
                self.assertEqual(status, 200)
                self.assertEqual(list(body), ["frame"])
                frame = body["frame"]
                self.assertEqual(frame, frame.lower())
                # magic 5050, version 01, flags 00, sequence, opcode, length 0002
                self.assertEqual(frame[:24], f"5050010001020304{opcode:04x}0002")
                self.assertEqual(frame[24:28], "cafe")

                status, decoded = self.stream(frame, True)
                self.assertEqual(status, 200)
                self.assertEqual(
                    decoded["events"],
                    [{"offset": 0, "channel": channel, "sequence": 0x01020304, "data": "cafe"}],
                )

    def test_empty_data_and_sequence_bounds(self) -> None:
        status, body = self.encode("log", 0, "")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["frame"]), 32)  # 16 bytes, no payload

        status, body = self.encode("debug", 0xFFFFFFFF, "")
        self.assertEqual(status, 200)
        status, decoded = self.stream(body["frame"], True)
        self.assertEqual(decoded["events"][0]["sequence"], 0xFFFFFFFF)

    def test_data_kept_in_order_max_size(self) -> None:
        payload = bytes(range(256)).hex()
        status, body = self.encode("serial", 7, payload)
        self.assertEqual(status, 200)
        status, decoded = self.stream(body["frame"], True)
        self.assertEqual(decoded["events"][0]["data"], payload)

        payload = "ab" * MAX_PAYLOAD
        status, body = self.encode("serial", 7, payload)
        self.assertEqual(status, 200)
        status, decoded = self.stream(body["frame"], True)
        self.assertEqual(status, 200)
        self.assertEqual(decoded["events"][0]["data"], payload)

        status, resp = self.encode("serial", 7, "ab" * (MAX_PAYLOAD + 1))
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_uppercase_hex_accepted(self) -> None:
        status, body = self.encode("debug", 1, "AABB")
        self.assertEqual(status, 200)
        status, decoded = self.stream(body["frame"], True)
        self.assertEqual(decoded["events"][0]["data"], "aabb")

    def test_field_errors(self) -> None:
        good = {"channel": "debug", "sequence": 1, "data": ""}
        cases = [
            {},
            {"sequence": 1, "data": ""},
            {"channel": "debug", "data": ""},
            {"channel": "debug", "sequence": 1},
            {**good, "extra": 1},
            {**good, "channel": "trace"},
            {**good, "channel": "DEBUG"},
            {**good, "channel": 0},
            {**good, "channel": None},
            {**good, "sequence": -1},
            {**good, "sequence": 1 << 32},
            {**good, "sequence": 1.5},
            {**good, "sequence": True},
            {**good, "sequence": "1"},
            {**good, "data": "abc"},
            {**good, "data": "0xab"},
            {**good, "data": "ab cd"},
            {**good, "data": "zz"},
            {**good, "data": 5},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post_json(ENCODE_PATH, body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_request_errors(self) -> None:
        status, resp = self.post(ENCODE_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for body in ([1, 2], "text", 42, None):
            with self.subTest(body=body):
                status, resp = self.post_json(ENCODE_PATH, body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")


class DecodeChannelStreamTest(ChannelHttpTest):
    def frame(self, **kw) -> bytes:
        return build_frame(**kw)

    def test_empty_data(self) -> None:
        for eof in (False, True):
            with self.subTest(eof=eof):
                status, body = self.stream("", eof)
                self.assertEqual(status, 200)
                self.assertEqual(
                    body,
                    {"events": [], "errors": [], "discarded": 0, "remainder": ""},
                )
                self.assertEqual(set(body), {"events", "errors", "discarded", "remainder"})

    def test_event_item_shape(self) -> None:
        frame = self.frame(flags=0, sequence=5, opcode=2, payload=b"\x01\x02")
        status, body = self.stream(frame.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["events"],
            [{"offset": 0, "channel": "serial", "sequence": 5, "data": "0102"}],
        )
        self.assertEqual(set(body["events"][0]), {"offset", "channel", "sequence", "data"})

    def test_events_in_offset_order_with_duplicate_sequences(self) -> None:
        f1 = self.frame(flags=0, sequence=1, opcode=1)
        f2 = self.frame(flags=0, sequence=1, opcode=2)
        f3 = self.frame(flags=0, sequence=1, opcode=3)
        status, body = self.stream((f1 + f2 + f3).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            [(e["offset"], e["channel"], e["sequence"]) for e in body["events"]],
            [(0, "debug", 1), (len(f1), "serial", 1), (2 * len(f1), "log", 1)],
        )
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 0)

    def test_noise_before_event_is_discarded(self) -> None:
        frame = self.frame(opcode=1)
        status, body = self.stream((b"\xaa\xbb" + frame).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["events"][0]["offset"], 2)

    def test_nonzero_flags_reports_unsupported_flags_and_skips_frame(self) -> None:
        bad = self.frame(flags=1, sequence=9, opcode=1, payload=b"x")
        good = self.frame(opcode=3, payload=b"y")
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [
            {"offset": len(bad), "channel": "log", "sequence": 0, "data": "79"}
        ])
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_flags"}])
        self.assertEqual(body["discarded"], len(bad))

    def test_unknown_opcode_reports_unsupported_channel(self) -> None:
        bad = self.frame(flags=0, opcode=0x0004)
        good = self.frame(opcode=2)
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0]["channel"], "serial")
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_channel"}])
        self.assertEqual(body["discarded"], len(bad))

    def test_flags_and_opcode_both_bad_reports_only_unsupported_flags(self) -> None:
        bad = self.frame(flags=0x80, opcode=0xFFFF)
        status, body = self.stream(bad.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_flags"}])
        self.assertEqual(body["discarded"], len(bad))

    def test_unsupported_frame_discarded_as_whole_frame(self) -> None:
        # Bytes inside the rejected payload happen to look like magic
        # 0x50 0x50; skipping the frame as a whole must never rescan them.
        bad = self.frame(flags=1, opcode=1, payload=b"\x50\x50abc")
        status, body = self.stream(bad.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_flags"}])
        self.assertEqual(body["discarded"], len(bad))
        self.assertEqual(body["events"], [])

    def test_inherited_v1_error_codes_and_resync(self) -> None:
        bad_version = self.frame(version=2, opcode=1)
        good = self.frame(opcode=2)
        bad_crc = bytearray(self.frame(opcode=3))
        bad_crc[-1] ^= 0xFF
        good2 = self.frame(opcode=1)
        blob = bad_version + good + bytes(bad_crc) + good2
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            [(e["offset"], e["code"]) for e in body["errors"]],
            [
                (0, "unsupported_version"),
                (len(bad_version) + len(good), "checksum_mismatch"),
            ],
        )
        self.assertEqual(
            [e["channel"] for e in body["events"]],
            ["serial", "debug"],
        )

    def test_errors_sorted_by_offset_mixed_with_events(self) -> None:
        bad_flags = self.frame(flags=1, opcode=1)
        good1 = self.frame(opcode=1)
        bad_opcode = self.frame(opcode=99)
        good2 = self.frame(opcode=2)
        blob = bad_flags + good1 + bad_opcode + good2
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        offsets = [e["offset"] for e in body["errors"]]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(
            [(e["offset"], e["code"]) for e in body["errors"]],
            [
                (0, "unsupported_flags"),
                (len(bad_flags) + len(good1), "unsupported_channel"),
            ],
        )
        self.assertEqual(
            [e["offset"] for e in body["events"]],
            [len(bad_flags), len(bad_flags) + len(good1) + len(bad_opcode)],
        )

    def test_invalid_length_resyncs(self) -> None:
        bad = self.frame(length=MAX_PAYLOAD + 1)
        good = self.frame(opcode=1)
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_length"}])
        self.assertEqual(body["events"][0]["offset"], len(bad))
        self.assertEqual(body["discarded"], len(bad))

    def test_partial_candidate_remainder_then_completes_on_resubmit(self) -> None:
        frame = self.frame(opcode=3, sequence=42, payload=b"abc")
        split = HEADER_LEN + 1
        head, tail = frame[:split], frame[split:]

        status, body = self.stream(head.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"events": [], "errors": [], "discarded": 0, "remainder": head.hex()})

        status, body = self.stream((head + tail).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(
            body["events"],
            [{"offset": 0, "channel": "log", "sequence": 42, "data": "616263"}],
        )

    def test_lone_0x50_remainder_and_eof_truncated(self) -> None:
        status, body = self.stream("50", False)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"events": [], "errors": [], "discarded": 0, "remainder": "50"})

        status, body = self.stream("0050", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [{"offset": 1, "code": "truncated_frame"}])
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], "")

    def test_truncated_tail_at_eof(self) -> None:
        frame = self.frame(opcode=1)
        tail = self.frame(opcode=2)[:5]
        status, body = self.stream((frame + tail).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["errors"], [{"offset": len(frame), "code": "truncated_frame"}])
        self.assertEqual(body["discarded"], len(tail))
        self.assertEqual(body["remainder"], "")

    def test_remainder_lowercase_with_uppercase_input(self) -> None:
        frame = self.frame(opcode=1)
        partial = frame[: HEADER_LEN + 1]
        status, body = self.stream(partial.hex().upper(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], partial.hex())

    def test_size_limit(self) -> None:
        status, body = self.stream("00" * (MAX_PAYLOAD * 256), True)  # exactly 1 MiB
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], MAX_PAYLOAD * 256)

        status, resp = self.stream("00" * (MAX_PAYLOAD * 256 + 1), True)
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_validation_errors(self) -> None:
        status, resp = self.stream_raw(b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for raw in (b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.stream_raw(raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

        good = {"data": "", "eof": False}
        cases = [
            {},
            {"data": ""},
            {"eof": False},
            {**good, "extra": 1},
            {"data": None, "eof": False},
            {"data": 5, "eof": False},
            {"data": "abc", "eof": False},
            {"data": "zz", "eof": False},
            {"data": "", "eof": 0},
            {"data": "", "eof": "false"},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post_json(DECODE_PATH, body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")


if __name__ == "__main__":
    unittest.main()
