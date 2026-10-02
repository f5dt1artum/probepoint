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
            wire += bytes([0x7D, byte ^ 0x20])
        else:
            wire.append(byte)
    return b"$" + bytes(wire) + b"#" + f"{sum(wire) % 256:02x}".encode("ascii")


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
        self.assertEqual(body, {"packet": "24233030"})  # "$#00"

    def test_simple_payload(self) -> None:
        status, body = self.encode("4142")  # "AB", sum 0x83
        self.assertEqual(status, 200)
        self.assertEqual(body, {"packet": "244142233833"})

    def test_escapes_special_bytes(self) -> None:
        status, body = self.encode("24237d2a")
        self.assertEqual(status, 200)
        # Each special byte becomes 0x7d followed by byte ^ 0x20; the
        # checksum sums the escaped on-wire bytes (0x62 mod 256).
        self.assertEqual(body, {"packet": "247d047d037d5d7d0a233632"})

    def test_unescaped_specials_round_trip(self) -> None:
        # Bytes that need no escaping pass through unchanged.
        status, body = self.encode("00ff80")
        self.assertEqual(status, 200)
        wire = bytes([0x00, 0xFF, 0x80])
        expected = b"$" + wire + b"#" + f"{sum(wire) % 256:02x}".encode("ascii")
        self.assertEqual(body, {"packet": expected.hex()})

    def test_uppercase_hex_accepted_output_lowercase(self) -> None:
        status, body = self.encode("AB")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"packet": "24ab236162"})

    def test_payload_size_limit(self) -> None:
        status, body = self.encode("00" * MAX_PAYLOAD)
        self.assertEqual(status, 200)
        status, resp = self.encode("00" * (MAX_PAYLOAD + 1))
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_not_json_object(self) -> None:
        status, resp = self.post(ENCODE_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for raw in (b"[1, 2]", b'"text"', b"42", b"null"):
            with self.subTest(raw=raw):
                status, resp = self.post(ENCODE_PATH, raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        cases = [
            {},
            {"payload": "", "extra": 1},
            {"payload": None},
            {"payload": 5},
            {"payload": []},
            {"payload": "abc"},  # odd length
            {"payload": "0x50"},  # prefix
            {"payload": "50 50"},  # separator
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
        packet = build_packet(b"OK")
        status, body = self.stream(packet.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "4f4b"}])
        self.assertEqual(body["controls"], [])
        self.assertEqual(body["errors"], [])
        self.assertEqual(body["discarded"], 0)
        self.assertEqual(body["remainder"], "")

    def test_item_shapes(self) -> None:
        blob = b"+" + build_packet(b"x") + b"$a#00"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(set(body["packets"][0]), {"offset", "payload"})
        self.assertEqual(set(body["controls"][0]), {"offset", "type"})
        self.assertEqual(set(body["errors"][0]), {"offset", "code"})

    def test_ack_and_nack_controls(self) -> None:
        status, body = self.stream("2b2d", True)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["controls"],
            [{"offset": 0, "type": "ack"}, {"offset": 1, "type": "nack"}],
        )
        self.assertEqual(body["discarded"], 0)

    def test_noise_is_discarded(self) -> None:
        packet = build_packet(b"OK")
        blob = b"\xaa\xbb" + packet
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["packets"][0]["offset"], 2)

    def test_multiple_packets_in_order(self) -> None:
        p1 = build_packet(b"one")
        p2 = build_packet(b"two")
        status, body = self.stream((p1 + b"+" + p2).hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual([p["payload"] for p in body["packets"]], [b"one".hex(), b"two".hex()])
        self.assertEqual([p["offset"] for p in body["packets"]], [0, len(p1) + 1])
        self.assertEqual(body["controls"], [{"offset": len(p1), "type": "ack"}])

    def test_escaped_payload_is_unescaped(self) -> None:
        packet = build_packet(b"\x24\x23\x7d\x2a")
        status, body = self.stream(packet.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["packets"], [{"offset": 0, "payload": "24237d2a"}])
        self.assertEqual(body["errors"], [])

    def test_uppercase_checksum_chars_accepted(self) -> None:
        packet = build_packet(b"OK")  # checksum 0x9a
        self.assertTrue(packet.endswith(b"9a"))
        blob = packet[:-2] + b"9A"
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["packets"]), 1)
        self.assertEqual(body["errors"], [])

    def test_nested_start_restarts_candidate(self) -> None:
        good = build_packet(b"b")
        blob = b"$a" + good
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "nested_start"}])
        self.assertEqual(body["packets"], [{"offset": 2, "payload": "62"}])
        self.assertEqual(body["discarded"], 2)

    def test_invalid_checksum_chars(self) -> None:
        blob = b"$a#zz" + build_packet(b"q")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_checksum"}])
        self.assertEqual(body["packets"], [{"offset": 5, "payload": "71"}])
        self.assertEqual(body["discarded"], 5)

    def test_checksum_mismatch(self) -> None:
        blob = b"$a#00" + build_packet(b"q")
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "checksum_mismatch"}])
        self.assertEqual(body["packets"], [{"offset": 5, "payload": "71"}])
        self.assertEqual(body["discarded"], 5)

    def test_invalid_length_when_payload_exceeds_limit(self) -> None:
        blob = b"$" + b"A" * (MAX_PAYLOAD + 1)
        status, body = self.stream(blob.hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_length"}])
        self.assertEqual(body["discarded"], len(blob))
        self.assertEqual(body["remainder"], "")

    def test_invalid_length_then_later_packet(self) -> None:
        good = build_packet(b"q")
        blob = b"$" + b"A" * (MAX_PAYLOAD + 1) + good
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(body["errors"], [{"offset": 0, "code": "invalid_length"}])
        self.assertEqual(body["packets"], [{"offset": MAX_PAYLOAD + 2, "payload": "71"}])

    def test_max_payload_accepted(self) -> None:
        packet = build_packet(b"A" * MAX_PAYLOAD)
        status, body = self.stream(packet.hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["packets"]), 1)
        self.assertEqual(body["errors"], [])

    def test_truncated_at_eof(self) -> None:
        for partial in (b"$", b"$ab", b"$ab#", b"$ab#1", b"$}", b"$a}"):  # various cuts
            with self.subTest(partial=partial):
                status, body = self.stream(partial.hex(), True)
                self.assertEqual(status, 200)
                self.assertEqual(body["packets"], [])
                self.assertEqual(body["errors"], [{"offset": 0, "code": "truncated_packet"}])
                self.assertEqual(body["discarded"], len(partial))
                self.assertEqual(body["remainder"], "")

    def test_packet_then_truncated_tail_at_eof(self) -> None:
        packet = build_packet(b"OK")
        status, body = self.stream((packet + b"$ab").hex(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["packets"]), 1)
        self.assertEqual(body["errors"], [{"offset": len(packet), "code": "truncated_packet"}])
        self.assertEqual(body["discarded"], 3)
        self.assertEqual(body["remainder"], "")

    def test_incomplete_candidate_waits_in_remainder(self) -> None:
        for partial in (b"$", b"$ab", b"$ab#", b"$ab#1", b"$}", b"$a}"):  # various cuts
            with self.subTest(partial=partial):
                status, body = self.stream(partial.hex(), False)
                self.assertEqual(status, 200)
                self.assertEqual(body["packets"], [])
                self.assertEqual(body["errors"], [])
                self.assertEqual(body["discarded"], 0)
                self.assertEqual(body["remainder"], partial.hex())

    def test_noise_then_partial_remainder_starts_at_dollar(self) -> None:
        status, body = self.stream((b"\xaa\xbb$ab").hex(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], 2)
        self.assertEqual(body["remainder"], "246162")

    def test_partial_candidate_waits_then_completes_on_resubmit(self) -> None:
        packet = build_packet(b"hello")
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
        self.assertEqual(body["packets"], [{"offset": 0, "payload": b"hello".hex()}])
        self.assertEqual(body["remainder"], "")

    def test_uppercase_hex_accepted_remainder_lowercase(self) -> None:
        packet = build_packet(b"OK")
        status, body = self.stream(packet.hex().upper(), True)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["packets"]), 1)

        partial = packet[:3]
        status, body = self.stream(partial.hex().upper(), False)
        self.assertEqual(status, 200)
        self.assertEqual(body["remainder"], partial.hex())

    def test_arrays_sorted_by_offset(self) -> None:
        blob = (
            b"\x00"  # noise
            b"+"
            + b"$a#00"  # checksum_mismatch
            + b"-"
            + build_packet(b"OK")
            + b"$x#zz"  # invalid_checksum
        )
        status, body = self.stream(blob.hex(), True)
        self.assertEqual(status, 200)
        for key in ("packets", "controls", "errors"):
            offsets = [item["offset"] for item in body[key]]
            self.assertEqual(offsets, sorted(offsets), key)
        self.assertEqual(
            [(e["offset"], e["code"]) for e in body["errors"]],
            [(2, "checksum_mismatch"), (14, "invalid_checksum")],
        )
        self.assertEqual(body["discarded"], 1 + 5 + 5)

    def test_size_limit(self) -> None:
        status, body = self.stream("00" * MAX_STREAM_DATA, True)  # exactly 1 MiB
        self.assertEqual(status, 200)
        self.assertEqual(body["discarded"], MAX_STREAM_DATA)

        status, resp = self.stream("00" * (MAX_STREAM_DATA + 1), True)
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")


class DecodeStreamValidationTest(RspHttpTest):
    def test_not_json_object(self) -> None:
        status, resp = self.post(STREAM_PATH, b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for raw in (b"[1, 2]", b'"text"', b"42", b"null"):
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
            {"data": [], "eof": False},
            {"data": "abc", "eof": False},  # odd length
            {"data": "0x24", "eof": False},  # prefix
            {"data": "24 23", "eof": False},  # separator
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
