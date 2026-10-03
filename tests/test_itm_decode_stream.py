import json
import unittest
import urllib.error
import urllib.request

from probepoint.itm import MAX_STREAM_DATA
from probepoint.server import make_server

PATH = "/v1/trace/itm/decode-stream"


def source_packet(source="software", port=0, payload=b"\x00"):
    size_code = {1: 1, 2: 2, 4: 3}[len(payload)]
    header = (port << 3) | (0x04 if source == "hardware" else 0) | size_code
    return bytes([header]) + payload


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


class DecodeItmStreamTest(StreamHttpTest):
    def test_empty_data(self) -> None:
        for eof in (False, True):
            with self.subTest(eof=eof):
                status, body = self.stream("", eof)
                self.assertEqual(status, 200)
                self.assertEqual(
                    body,
                    {"events": [], "errors": [], "discarded": 0, "remainder": ""},
                )

    def test_source_packet_shapes_and_sizes(self) -> None:
        blob = (
            source_packet("software", 3, b"\xaa")
            + source_packet("hardware", 31, b"\xbb\xcc")
            + source_packet("software", 0, b"\x01\x02\x03\x04")
        )
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(
            body["events"],
            [
                {
                    "offset": 0,
                    "type": "source",
                    "source": "software",
                    "port": 3,
                    "size": 1,
                    "data": "aa",
                },
                {
                    "offset": 2,
                    "type": "source",
                    "source": "hardware",
                    "port": 31,
                    "size": 2,
                    "data": "bbcc",
                },
                {
                    "offset": 5,
                    "type": "source",
                    "source": "software",
                    "port": 0,
                    "size": 4,
                    "data": "01020304",
                },
            ],
        )

    def test_uppercase_hex_accepted_remainder_lowercase(self) -> None:
        packet = source_packet("software", 1, b"\xca\xfe")
        status, body = self.stream(packet.hex().upper(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)

        status, body = self.stream(packet[:1].hex().upper(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], packet[:1].hex())

    def test_sync_packet_consumes_last_five_zeros(self) -> None:
        blob = b"\x00" * 7 + b"\x80"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 2, "type": "sync"}])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 2)  # two leading zeros are padding
        self.assertEqual(body["remainder"], "")

    def test_exactly_five_zeros_sync(self) -> None:
        status, body = self.stream((b"\x00" * 5 + b"\x80").hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 0, "type": "sync"}])
        self.assertEqual(body["discarded"], 0)

    def test_sync_end_with_too_few_zeros_is_unsupported(self) -> None:
        blob = b"\x00\x00\x80"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [{"offset": 2, "code": "unsupported_packet"}])
        self.assertEqual(body["discarded"], 3)

    def test_lone_sync_end_is_unsupported(self) -> None:
        status, body = self.stream("80", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_packet"}])
        self.assertEqual(body["discarded"], 1)

    def test_overflow_event(self) -> None:
        blob = source_packet("software", 0, b"\x11") + b"\x70" + source_packet("hardware", 2, b"\x22")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"][1], {"offset": 2, "type": "overflow"})
        self.assertEqual(body["discarded"], 0)

    def test_padding_zeros_before_packet_are_discarded(self) -> None:
        blob = b"\x00\x00\x00" + source_packet("software", 5, b"\x99")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["events"][0]["offset"], 3)

    def test_trailing_zeros_kept_in_remainder_then_sync(self) -> None:
        status, body = self.stream("00" * 4, False)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "00000000")

        # Caller concatenates the remainder with the new fragment.
        status, body = self.stream("00" * 4 + "0080", False)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 0, "type": "sync"}])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")

    def test_trailing_zeros_remainder_capped_at_five(self) -> None:
        status, body = self.stream("00" * 8, False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "00" * 5)

    def test_trailing_zeros_discarded_at_eof(self) -> None:
        status, body = self.stream("00" * 3, True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "")

    def test_unsupported_packet_resyncs(self) -> None:
        packet = source_packet("software", 1, b"\x42")
        blob = b"\x10" + packet + b"\xf0" + packet
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["errors"],
            [
                {"offset": 0, "code": "unsupported_packet"},
                {"offset": 3, "code": "unsupported_packet"},
            ],
        )
        self.assertEqual([e["offset"] for e in body["events"]], [1, 4])
        self.assertEqual(body["discarded"], 2)

    def test_incomplete_payload_waits_then_completes_on_resubmit(self) -> None:
        packet = source_packet("hardware", 7, b"\xde\xad\xbe\xef")
        head, tail = packet[:3], packet[3:]

        status, body = self.stream(head.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"events": [], "errors": [], "discarded": 0, "remainder": head.hex()},
        )

        status, body = self.stream((head + tail).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(
            body["events"],
            [
                {
                    "offset": 0,
                    "type": "source",
                    "source": "hardware",
                    "port": 7,
                    "size": 4,
                    "data": "deadbeef",
                }
            ],
        )

    def test_truncated_packet_at_eof(self) -> None:
        packet = source_packet("software", 0, b"\x01\x02")
        good = source_packet("software", 0, b"\x09")
        blob = good + packet[:1]
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["errors"], [{"offset": len(good), "code": "truncated_packet"}])
        self.assertEqual(body["discarded"], 1)
        self.assertEqual(body["remainder"], "")

    def test_errors_do_not_block_later_events(self) -> None:
        blob = b"\x80" + source_packet("software", 2, b"\x77") + b"\x00" * 5 + b"\x80"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_packet"}])
        self.assertEqual(
            [(e["offset"], e["type"]) for e in body["events"]],
            [(1, "source"), (3, "sync")],
        )
        self.assertEqual(body["discarded"], 1)

    def test_size_limit(self) -> None:
        status, body = self.stream("01aa" * (MAX_STREAM_DATA // 2), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), MAX_STREAM_DATA // 2)

        status, resp = self.stream("00" * (MAX_STREAM_DATA + 1), True)
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")


class DecodeItmStreamValidationTest(StreamHttpTest):
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
