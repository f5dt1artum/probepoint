import json
import struct
import unittest
import urllib.error
import urllib.request
import zlib

from probepoint.frames import HEADER_LEN, MAX_PAYLOAD
from probepoint.server import make_server

ENCODE_PATH = "/v1/channels/encode"
STREAM_PATH = "/v1/channels/decode-stream"

OPCODES = {"debug": 0x0001, "serial": 0x0002, "log": 0x0003}


def build_frame(flags=0, sequence=0, opcode=0, payload=b"", version=1, length=None):
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

    def encode(self, body: dict) -> tuple[int, dict]:
        return self.post(ENCODE_PATH, json.dumps(body).encode("utf-8"))

    def stream(self, data: str, eof: bool) -> tuple[int, dict]:
        return self.post(STREAM_PATH, json.dumps({"data": data, "eof": eof}).encode("utf-8"))


class EncodeTest(ChannelHttpTest):
    def test_each_channel_maps_to_its_opcode(self) -> None:
        for channel, opcode in OPCODES.items():
            with self.subTest(channel=channel):
                status, body = self.encode(
                    {"channel": channel, "sequence": 0xAABBCCDD, "data": "cafe"}
                )
                self.assertEqual(status, 200)
                self.assertEqual(set(body), {"frame"})
                frame = bytes.fromhex(body["frame"])
                self.assertEqual(body["frame"], frame.hex())  # lowercase
                magic, version, flags, sequence, got_opcode, length = struct.unpack(
                    ">HBBIHH", frame[:HEADER_LEN]
                )
                self.assertEqual((magic, version, flags), (0x5050, 1, 0))
                self.assertEqual(sequence, 0xAABBCCDD)
                self.assertEqual(got_opcode, opcode)
                self.assertEqual(length, 2)
                self.assertEqual(frame[HEADER_LEN : HEADER_LEN + 2], b"\xca\xfe")
                (crc,) = struct.unpack(">I", frame[HEADER_LEN + 2 :])
                self.assertEqual(crc, zlib.crc32(frame[2 : HEADER_LEN + 2]))

    def test_empty_and_max_payload(self) -> None:
        status, body = self.encode({"channel": "debug", "sequence": 0, "data": ""})
        self.assertEqual(status, 200)
        self.assertEqual(len(bytes.fromhex(body["frame"])), HEADER_LEN + 4)

        status, body = self.encode(
            {"channel": "log", "sequence": 7, "data": "ab" * MAX_PAYLOAD}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(bytes.fromhex(body["frame"])), HEADER_LEN + MAX_PAYLOAD + 4)

    def test_encoded_frame_roundtrips_through_frames_decode(self) -> None:
        status, body = self.encode({"channel": "serial", "sequence": 42, "data": "00ff"})
        self.assertEqual(status, 200)
        status, decoded = self.post(
            "/v1/frames/decode", json.dumps({"frame": body["frame"]}).encode("utf-8")
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            decoded,
            {"version": 1, "flags": 0, "sequence": 42, "opcode": 0x0002, "payload": "00ff"},
        )

    def test_not_json_object(self) -> None:
        for raw in (b"not json", b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(ENCODE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        good = {"channel": "debug", "sequence": 1, "data": ""}
        cases = [
            {},
            {"channel": "debug", "sequence": 1},
            {"sequence": 1, "data": ""},
            {"channel": "debug", "data": ""},
            {**good, "extra": 1},
            {**good, "channel": "DEBUG"},
            {**good, "channel": "trace"},
            {**good, "channel": ""},
            {**good, "channel": 1},
            {**good, "channel": None},
            {**good, "sequence": -1},
            {**good, "sequence": 1 << 32},
            {**good, "sequence": 1.5},
            {**good, "sequence": True},
            {**good, "sequence": "1"},
            {**good, "data": 5},
            {**good, "data": None},
            {**good, "data": "abc"},  # odd length
            {**good, "data": "0x50"},  # prefix
            {**good, "data": "zz"},
            {**good, "data": "ab" * (MAX_PAYLOAD + 1)},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.encode(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")


class DecodeStreamTest(ChannelHttpTest):
    def frame(self, channel="debug", **kw) -> bytes:
        return build_frame(opcode=OPCODES[channel], **kw)

    def test_empty_data(self) -> None:
        for eof in (False, True):
            with self.subTest(eof=eof):
                status, body = self.stream("", eof)
                self.assertEqual(status, 200)
                self.assertEqual(
                    body,
                    {"events": [], "errors": [], "discarded": 0, "remainder": ""},
                )

    def test_single_event_shape(self) -> None:
        frame = self.frame(channel="serial", sequence=99, payload=b"\xCA\xFE")
        status, body = self.stream(frame.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "events": [
                    {"offset": 0, "channel": "serial", "sequence": 99, "data": "cafe"}
                ],
                "errors": [],
                "discarded": 0,
                "remainder": "",
            },
        )

    def test_all_channels_and_duplicate_sequences_in_order(self) -> None:
        frames = [
            self.frame(channel="log", sequence=1, payload=b"a"),
            self.frame(channel="debug", sequence=1, payload=b""),
            self.frame(channel="serial", sequence=1, payload=b"\x00"),
        ]
        blob = b"".join(frames)
        status, body = self.stream(blob.hex().upper(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            [(e["offset"], e["channel"], e["sequence"]) for e in body["events"]],
            [
                (0, "log", 1),
                (len(frames[0]), "debug", 1),
                (len(frames[0]) + len(frames[1]), "serial", 1),
            ],
        )
        self.assertEqual([e["data"] for e in body["events"]], ["61", "", "00"])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 0)

    def test_noise_before_frame_is_discarded(self) -> None:
        frame = self.frame(sequence=5)
        status, body = self.stream((b"\xaa\xbb" + frame).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["events"][0]["offset"], 2)

    def test_nonzero_flags_reported_and_frame_fully_discarded(self) -> None:
        bad = self.frame(channel="debug", flags=3, sequence=1)
        good = self.frame(channel="log", sequence=2)
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_flags"}])
        self.assertEqual(body["discarded"], len(bad))
        self.assertEqual(
            body["events"],
            [{"offset": len(bad), "channel": "log", "sequence": 2, "data": ""}],
        )

    def test_unknown_opcode_reported_and_frame_fully_discarded(self) -> None:
        bad = build_frame(flags=0, sequence=1, opcode=0x0004, payload=b"xy")
        good = self.frame(channel="debug", sequence=2)
        status, body = self.stream((bad + good).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_channel"}])
        self.assertEqual(body["discarded"], len(bad))
        self.assertEqual([e["sequence"] for e in body["events"]], [2])

    def test_flags_and_opcode_both_bad_reports_only_unsupported_flags(self) -> None:
        bad = build_frame(flags=1, sequence=1, opcode=0x00FF)
        status, body = self.stream(bad.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_flags"}])
        self.assertEqual(body["discarded"], len(bad))

    def test_base_stream_errors_still_apply(self) -> None:
        bad_version = build_frame(version=2)
        bad_crc = bytearray(self.frame())
        bad_crc[-1] ^= 0xFF
        good = self.frame(channel="serial", sequence=9)
        blob = bad_version + bytes(bad_crc) + good
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["errors"],
            [
                {"offset": 0, "code": "unsupported_version"},
                {"offset": len(bad_version), "code": "checksum_mismatch"},
            ],
        )
        self.assertEqual([e["offset"] for e in body["events"]], [len(bad_version) + len(bad_crc)])

    def test_partial_candidate_waits_then_completes_on_resubmit(self) -> None:
        frame = self.frame(channel="log", sequence=42, payload=b"abc")
        split = HEADER_LEN + 1
        head, tail = frame[:split], frame[split:]

        status, body = self.stream(head.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"events": [], "errors": [], "discarded": 0, "remainder": head.hex()}
        )

        status, body = self.stream((head + tail).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(body["events"][0]["data"], "616263")

    def test_truncated_at_eof_reports_error(self) -> None:
        frame = self.frame()
        for partial in (frame[:1], frame[: HEADER_LEN - 1], frame[:-1]):
            with self.subTest(cut=len(partial)):
                status, body = self.stream(partial.hex(), True)
                self.assertEqual(status, 200)
                self.assertEqual(body["events"], [])
                self.assertEqual(body["errors"], [{"offset": 0, "code": "truncated_frame"}])
                self.assertEqual(body["discarded"], len(partial))
                self.assertEqual(body["remainder"], "")

    def test_size_limit(self) -> None:
        status, body = self.stream("00" * (1 << 20), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 1 << 20)

        status, resp = self.stream("00" * ((1 << 20) + 1), True)
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")


class DecodeStreamValidationTest(ChannelHttpTest):
    def test_not_json_object(self) -> None:
        for raw in (b"not json", b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(STREAM_PATH, raw)
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
            {"data": "abc", "eof": False},
            {"data": "0x50", "eof": False},
            {"data": "zz", "eof": False},
            {"data": "", "eof": 0},
            {"data": "", "eof": "false"},
            {"data": "", "eof": None},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post(STREAM_PATH, json.dumps(body).encode("utf-8"))
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")


if __name__ == "__main__":
    unittest.main()
