import json
import unittest
import urllib.error
import urllib.request

from probepoint.itm import MAX_STREAM_DATA
from probepoint.server import make_server

PATH = "/v1/trace/itm/decode-stream"


def source_packet(port=0, hardware=False, payload=b"\x00"):
    size_code = {1: 1, 2: 2, 4: 3}[len(payload)]
    header = (port << 3) | (0x04 if hardware else 0) | size_code
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

    def test_source_packet_sizes_and_fields(self) -> None:
        cases = [
            (source_packet(port=3, payload=b"\xab"), "software", 3, 1, "ab"),
            (source_packet(port=0, payload=b"\x01\x02"), "software", 0, 2, "0102"),
            (source_packet(port=31, hardware=True, payload=b"\xde\xad\xbe\xef"), "hardware", 31, 4, "deadbeef"),
        ]
        for packet, source, port, size, data in cases:
            with self.subTest(data=data):
                status, body = self.stream(packet.hex(), True)
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
                            "source": source,
                            "port": port,
                            "size": size,
                            "data": data,
                        }
                    ],
                )

    def test_event_and_error_item_shapes(self) -> None:
        status, body = self.stream(source_packet(payload=b"\x01").hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            set(body["events"][0]),
            {"offset", "type", "source", "port", "size", "data"},
        )

        status, body = self.stream("04", True)  # size code 0, not special
        self.assertEqual(status, 200)
        self.assertEqual(set(body["errors"][0]), {"offset", "code"})

        status, body = self.stream("70", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 0, "type": "overflow"}])

        status, body = self.stream("000000000080", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 0, "type": "sync"}])

    def test_sync_with_exactly_five_zeros(self) -> None:
        status, body = self.stream("000000000080", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 0, "type": "sync"}])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 0)

    def test_sync_with_extra_zeros_counts_padding(self) -> None:
        blob = b"\x00" * 8 + b"\x80"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 3, "type": "sync"}])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 3)

    def test_sync_after_source_packet(self) -> None:
        blob = source_packet(port=1, payload=b"\xff") + b"\x00" * 5 + b"\x80"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["events"],
            [
                {
                    "offset": 0,
                    "type": "source",
                    "source": "software",
                    "port": 1,
                    "size": 1,
                    "data": "ff",
                },
                {"offset": 2, "type": "sync"},
            ],
        )
        self.assertEqual(body["discarded"], 0)

    def test_short_zero_run_before_0x80_is_unsupported(self) -> None:
        blob = b"\x00" * 4 + b"\x80"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [{"offset": 4, "code": "unsupported_packet"}])
        self.assertEqual(body["discarded"], 5)

    def test_lone_0x80_is_unsupported(self) -> None:
        status, body = self.stream("80", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["errors"], [{"offset": 0, "code": "unsupported_packet"}])
        self.assertEqual(body["discarded"], 1)

    def test_overflow_event(self) -> None:
        blob = b"\x70" + source_packet(port=2, payload=b"\x01")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"][0], {"offset": 0, "type": "overflow"})
        self.assertEqual(body["events"][1]["offset"], 1)
        self.assertEqual(body["discarded"], 0)

    def test_unsupported_size_code_zero_resyncs(self) -> None:
        blob = b"\x04\x10" + source_packet(port=7, payload=b"\x2a")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["errors"],
            [
                {"offset": 0, "code": "unsupported_packet"},
                {"offset": 1, "code": "unsupported_packet"},
            ],
        )
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0]["offset"], 2)
        self.assertEqual(body["events"][0]["port"], 7)
        self.assertEqual(body["discarded"], 2)

    def test_padding_zeros_before_packet_are_discarded(self) -> None:
        blob = b"\x00\x00\x00" + source_packet(port=1, payload=b"\x01")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"][0]["offset"], 3)
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["errors"], [])

    def test_truncated_packet_waits_then_completes_on_resubmit(self) -> None:
        packet = source_packet(port=9, payload=b"\xde\xad\xbe\xef")
        head, tail = packet[:3], packet[3:]

        status, body = self.stream(head.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"events": [], "errors": [], "discarded": 0, "remainder": head.hex()},
        )

        # Stateless: caller concatenates the remainder with the new fragment.
        status, body = self.stream((head + tail).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], "")
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["events"][0]["offset"], 0)
        self.assertEqual(body["events"][0]["data"], "deadbeef")

    def test_truncated_packet_at_eof(self) -> None:
        packet = source_packet(port=1, payload=b"\x01\x02")
        for cut in (1, 2):
            with self.subTest(cut=cut):
                status, body = self.stream(packet[:cut].hex(), True)
                self.assertEqual(status, 200)
                self.assertEqual(body["events"], [])
                self.assertEqual(body["errors"], [{"offset": 0, "code": "truncated_packet"}])
                self.assertEqual(body["discarded"], cut)
                self.assertEqual(body["remainder"], "")

    def test_packet_then_truncated_tail_at_eof(self) -> None:
        good = source_packet(port=1, payload=b"\x01")
        tail = source_packet(port=2, payload=b"\xaa\xbb")[:1]
        status, body = self.stream((good + tail).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["errors"], [{"offset": len(good), "code": "truncated_packet"}])
        self.assertEqual(body["discarded"], len(tail))
        self.assertEqual(body["remainder"], "")

    def test_trailing_zeros_kept_as_remainder_up_to_five(self) -> None:
        status, body = self.stream("00" * 5, False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "00" * 5)

        status, body = self.stream("00" * 8, False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "00" * 5)

    def test_trailing_zeros_discarded_at_eof(self) -> None:
        for count in (1, 5, 8):
            with self.subTest(count=count):
                status, body = self.stream("00" * count, True)
                self.assertEqual(status, 200)
                self.assertEqual(body["events"], [])
                self.assertEqual(body["errors"], [])
                self.assertEqual(body["discarded"], count)
                self.assertEqual(body["remainder"], "")

    def test_kept_zeros_complete_sync_on_resubmit(self) -> None:
        status, body = self.stream("00" * 4, False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], "00" * 4)

        status, body = self.stream(("00" * 4 + "00" * 1 + "80"), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [{"offset": 0, "type": "sync"}])
        self.assertEqual(body["discarded"], 0)

    def test_uppercase_hex_accepted_remainder_lowercase(self) -> None:
        packet = source_packet(port=1, payload=b"\xab\xcd")
        status, body = self.stream(packet.hex().upper(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0]["data"], "abcd")

        status, body = self.stream(packet[:1].hex().upper(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], packet[:1].hex())

    def test_events_and_errors_sorted_by_offset(self) -> None:
        blob = (
            b"\x04"
            + source_packet(port=1, payload=b"\x01")
            + b"\x70"
            + b"\x80"
            + source_packet(port=2, payload=b"\x02")
        )
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        offsets = [e["offset"] for e in body["events"]]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(
            [(e["offset"], e["code"]) for e in body["errors"]],
            [(0, "unsupported_packet"), (4, "unsupported_packet")],
        )
        self.assertEqual([e["type"] for e in body["events"]], ["source", "overflow", "source"])

    def test_size_limit(self) -> None:
        status, body = self.stream("00" * MAX_STREAM_DATA, True)  # exactly 1 MiB
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], MAX_STREAM_DATA)

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
            {"data": "0x70", "eof": False},  # prefix
            {"data": "70 70", "eof": False},  # separator
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
