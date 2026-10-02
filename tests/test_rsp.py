import json
import unittest
import urllib.error
import urllib.request

from probepoint.rsp import MAX_PAYLOAD, MAX_STREAM_DATA
from probepoint.server import make_server

ENCODE_PATH = "/v1/rsp/encode"
STREAM_PATH = "/v1/rsp/decode-stream"


def build_packet(payload: bytes) -> bytes:
    wire = bytearray()
    for byte in payload:
        if byte in (0x24, 0x23, 0x7D, 0x2A):
            wire.append(0x7D)
            wire.append(byte ^ 0x20)
        else:
            wire.append(byte)
    checksum = sum(wire) % 256
    return b"$" + bytes(wire) + b"#" + f"{checksum:02x}".encode("ascii")


class RspHttpTest(unittest.TestCase):
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

    def encode(self, payload: str) -> tuple[int, dict]:
        return self.post(ENCODE_PATH, json.dumps({"payload": payload}).encode("utf-8"))

    def stream(self, data: str, eof: bool) -> tuple[int, dict]:
        return self.post(STREAM_PATH, json.dumps({"data": data, "eof": eof}).encode("utf-8"))


class EncodeTest(RspHttpTest):
    def test_empty_payload(self) -> None:
        status, body = self.encode("")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"packet": "24233030"})

    def test_simple_payload(self) -> None:
        status, body = self.encode("616263")  # "abc"
        self.assertEqual(status, 200)
        # sum(0x61, 0x62, 0x63) = 294 mod 256 = 0x26
        self.assertEqual(body, {"packet": "24616263233236"})

    def test_escapes_special_bytes(self) -> None:
        status, body = self.encode("24237d2a")
        self.assertEqual(status, 200)
        wire = bytes.fromhex("7d047d037d5d7d0a")
        checksum = sum(wire) % 256
        expected = b"$" + wire + b"#" + f"{checksum:02x}".encode("ascii")
        self.assertEqual(body, {"packet": expected.hex()})

    def test_roundtrip_through_decode_stream(self) -> None:
        payload = "24237d2a00ff"
        status, body = self.encode(payload)
        self.assertEqual(status, 200)
        status, decoded = self.stream(body["packet"], True)
        self.assertEqual(status, 200)
        self.assertEqual(decoded["packets"], [{"offset": 0, "payload": payload}])
        self.assertEqual(decoded["errors"], [])
        self.assertEqual(decoded["discarded"], 0)

    def test_max_payload_accepted(self) -> None:
        status, body = self.encode("00" * MAX_PAYLOAD)
        self.assertEqual(status, 200)
        self.assertEqual(body["packet"], "24" + "00" * MAX_PAYLOAD + "233030")

    def test_payload_too_long(self) -> None:
        status, body = self.encode("00" * (MAX_PAYLOAD + 1))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_validation(self) -> None:
        status, body = self.post(ENCODE_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

        for raw in (b"[1]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, body = self.post(ENCODE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_request")

        cases = [
            {},
            {"payload": "", "extra": 1},
            {"payload": None},
            {"payload": 5},
            {"payload": "abc"},  # odd length
            {"payload": "0x50"},
            {"payload": "zz"},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post(ENCODE_PATH, json.dumps(body).encode("utf-8"))
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")


class DecodeStreamTest(RspHttpTest):
    def test_empty_data(self) -> None:
        for eof in (False, True):
            with self.subTest(eof=eof):
                status, body = self.stream("", eof)
                self.assertEqual(status, 200)
                self.assertEqual(
                    body,
                    {
                        "packets": [],
                        "controls": [],
                        "errors": [],
                        "discarded": 0,
                        "remainder": "",
                    },
                )

    def test_single_packet_with_offset(self) -> None:
        blob = b"\xaa\xbb" + build_packet(b"abc")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 2, "payload": "616263"}])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], "")

    def test_packet_and_error_item_shapes(self) -> None:
        status, body = self.stream(build_packet(b"x").hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(set(body["packets"][0]), {"offset", "payload"})

        status, body = self.stream(b"$aa#00".hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(set(body["errors"][0]), {"offset", "code"})

    def test_empty_packet(self) -> None:
        status, body = self.stream("24233030", True)  # "$#00"
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": ""}])
        self.assertEqual(body["discarded"], 0)

    def test_controls_outside_candidates(self) -> None:
        status, body = self.stream("2b2d", True)  # "+-"
        self.assertEqual(status, 200)
        self.assertEqual(
            body["controls"],
            [{"offset": 0, "type": "ack"}, {"offset": 1, "type": "nack"}],
        )
        self.assertEqual(body["discarded"], 0)

    def test_control_bytes_inside_packet_are_payload(self) -> None:
        status, body = self.stream(build_packet(b"+-*").hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "2b2d2a"}])
        self.assertEqual(body["controls"], [])

    def test_noise_is_discarded(self) -> None:
        status, body = self.stream("aabbcc", True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [])
        self.assertEqual(body["controls"], [])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 3)

    def test_nested_start_restarts_candidate(self) -> None:
        blob = b"$ab" + build_packet(b"cd")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "nested_start"}])
        self.assertEqual(body["packets"], [{"offset": 3, "payload": "6364"}])
        self.assertEqual(body["discarded"], 3)

    def test_escaped_start_byte_is_not_nested(self) -> None:
        # 0x7d 0x04 is an escaped 0x24 payload byte, not a new candidate.
        status, body = self.stream(build_packet(b"$").hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "24"}])
        self.assertEqual(body["errors"], [])

    def test_invalid_checksum_chars(self) -> None:
        status, body = self.stream(b"$aa#zz".hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_checksum"}])
        self.assertEqual(body["packets"], [])
        self.assertEqual(body["discarded"], 6)

    def test_checksum_mismatch(self) -> None:
        status, body = self.stream(b"$aa#00".hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "checksum_mismatch"}])
        self.assertEqual(body["discarded"], 6)

    def test_uppercase_checksum_chars_accepted(self) -> None:
        packet = bytearray(build_packet(b"abc"))
        packet[-2:] = packet[-2:].upper()
        status, body = self.stream(bytes(packet).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "616263"}])

    def test_invalid_length(self) -> None:
        blob = b"$" + b"A" * (MAX_PAYLOAD + 1)
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_length"}])
        self.assertEqual(body["packets"], [])
        self.assertEqual(body["discarded"], len(blob))

    def test_error_does_not_block_later_packets(self) -> None:
        good = build_packet(b"ok")
        blob = b"$aa#00" + good
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "checksum_mismatch"}])
        self.assertEqual(body["packets"], [{"offset": 6, "payload": "6f6b"}])
        self.assertEqual(body["discarded"], 6)

    def test_partial_candidate_waits_then_completes_on_resubmit(self) -> None:
        packet = build_packet(b"abc")
        head, tail = packet[:4], packet[4:]

        status, body = self.stream(head.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "packets": [],
                "controls": [],
                "errors": [],
                "discarded": 0,
                "remainder": head.hex(),
            },
        )

        # Stateless: caller concatenates the remainder with the new fragment.
        status, body = self.stream((head + tail).hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "616263"}])
        self.assertEqual(body["remainder"], "")

    def test_incomplete_checksum_waits_for_more_data(self) -> None:
        for partial in (b"$aa#", b"$aa#0"):
            with self.subTest(partial=partial):
                status, body = self.stream(partial.hex(), False)
                self.assertEqual(status, 200)
                self.assertEqual(body["errors"], [])
                self.assertEqual(body["discarded"], 0)
                self.assertEqual(body["remainder"], partial.hex())

    def test_trailing_lone_escape_waits(self) -> None:
        status, body = self.stream(b"$a}".hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["remainder"], "24617d")

    def test_uppercase_hex_input_remainder_lowercase(self) -> None:
        partial = build_packet(b"abc")[:4]
        status, body = self.stream(partial.hex().upper(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], partial.hex())

    def test_truncated_at_eof_reports_error(self) -> None:
        packet = build_packet(b"abc")
        for partial in (b"$", b"$a", packet[:-1], packet[:-2]):
            with self.subTest(cut=len(partial)):
                status, body = self.stream(partial.hex(), True)
                self.assertEqual(status, 200)
                self.assertEqual(body["packets"], [])
                self.assertEqual(body["errors"], [{"offset": 0, "code": "truncated_packet"}])
                self.assertEqual(body["discarded"], len(partial))
                self.assertEqual(body["remainder"], "")

    def test_packet_then_truncated_tail_at_eof(self) -> None:
        good = build_packet(b"ok")
        tail = build_packet(b"no")[:3]
        status, body = self.stream((good + tail).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "6f6b"}])
        self.assertEqual(body["errors"], [{"offset": len(good), "code": "truncated_packet"}])
        self.assertEqual(body["discarded"], len(tail))
        self.assertEqual(body["remainder"], "")

    def test_offsets_sorted_across_arrays(self) -> None:
        blob = b"\x2b" + b"$aa#00" + build_packet(b"q") + b"\x2d"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["controls"][0], {"offset": 0, "type": "ack"})
        self.assertEqual(body["controls"][1]["type"], "nack")
        self.assertEqual(body["errors"], [{"offset": 1, "code": "checksum_mismatch"}])
        self.assertEqual(body["packets"][0]["payload"], "71")
        for key in ("packets", "controls", "errors"):
            offsets = [item["offset"] for item in body[key]]
            self.assertEqual(offsets, sorted(offsets))

    def test_validation(self) -> None:
        status, body = self.post(STREAM_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

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
            {"data": "", "eof": None},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post(STREAM_PATH, json.dumps(body).encode("utf-8"))
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_data_size_limit(self) -> None:
        status, body = self.stream("00" * MAX_STREAM_DATA, True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], MAX_STREAM_DATA)

        status, body = self.stream("00" * (MAX_STREAM_DATA + 1), True)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")


if __name__ == "__main__":
    unittest.main()
