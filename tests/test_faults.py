import json
import struct
import threading
import unittest
import urllib.error
import urllib.request

from probepoint.faults import analyze_cortex_m_fault
from probepoint.server import make_server

PATH = "/v1/faults/cortex-m/analyze"
U32_MAX = 0xFFFFFFFF


def encode_frame(words):
    return b"".join(struct.pack("<I", w) for w in words).hex()


VALID_WORDS = [0x10, 0x11, 0x12, 0x13, 0x14, 0xFFFF_FFFF, 0x0800_1235, 0x2100_0000]


def base_request(**overrides):
    body = {
        "stacked_frame": encode_frame(VALID_WORDS),
        "cfsr": 0,
        "hfsr": 0,
        "mmfar": 0x2000_0000,
        "bfar": 0x2000_1000,
    }
    body.update(overrides)
    return body


class AnalyzeCortexMFaultTest(unittest.TestCase):
    def analyze(self, body):
        return analyze_cortex_m_fault(body)

    def test_frame_decoding_and_thumb_bit(self):
        result = self.analyze(base_request())
        frame = result["frame"]
        self.assertEqual(
            frame,
            {
                "r0": 0x10,
                "r1": 0x11,
                "r2": 0x12,
                "r3": 0x13,
                "r12": 0x14,
                "lr": 0xFFFF_FFFF,
                "pc": 0x0800_1235,
                "xpsr": 0x2100_0000,
                "instruction_address": 0x0800_1234,
                "frame_valid": True,
            },
        )

    def test_cleared_thumb_bit_is_still_reported(self):
        words = VALID_WORDS.copy()
        words[7] = 0x0200_0000  # T bit (bit 24) clear
        result = self.analyze(base_request(stacked_frame=encode_frame(words)))
        self.assertFalse(result["frame"]["frame_valid"])
        self.assertEqual(result["frame"]["instruction_address"], 0x0800_1234)

    def test_status_echoed_verbatim(self):
        result = self.analyze(base_request(cfsr=0xDEAD_BEEF, hfsr=0xCAFE_BABE))
        self.assertEqual(result["status"], {"cfsr": 0xDEAD_BEEF, "hfsr": 0xCAFE_BABE})

    def test_cfsr_causes_in_ascending_bit_order(self):
        cfsr = (
            (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5)
            | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13)
            | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 24) | (1 << 25)
        )
        result = self.analyze(base_request(cfsr=cfsr))
        names = [c["name"] for c in result["causes"]]
        self.assertEqual(
            names,
            [
                "IACCVIOL", "DACCVIOL", "MUNSTKERR", "MSTKERR", "MLSPERR",
                "IBUSERR", "PRECISERR", "IMPRECISERR", "UNSTKERR", "STKERR", "LSPERR",
                "UNDEFINSTR", "INVSTATE", "INVPC", "NOCP", "UNALIGNED", "DIVBYZERO",
            ],
        )
        for cause in result["causes"]:
            self.assertEqual(set(cause), {"register", "bit", "name"})
            self.assertEqual(cause["register"], "cfsr")

    def test_hfsr_causes_after_cfsr_and_ascending(self):
        hfsr = (1 << 31) | (1 << 1) | (1 << 30)
        result = self.analyze(base_request(hfsr=hfsr))
        self.assertEqual(
            result["causes"],
            [
                {"register": "hfsr", "bit": 1, "name": "VECTTBL"},
                {"register": "hfsr", "bit": 30, "name": "FORCED"},
                {"register": "hfsr", "bit": 31, "name": "DEBUGEVT"},
            ],
        )

    def test_cfsr_precedes_hfsr_in_ordering(self):
        result = self.analyze(base_request(cfsr=1 << 25, hfsr=1 << 1))
        self.assertEqual(
            [(c["register"], c["bit"]) for c in result["causes"]],
            [("cfsr", 25), ("hfsr", 1)],
        )

    def test_undefined_bits_stay_in_status_only(self):
        # Undefined CFSR bits only: 2, 6, 14, 20-23, 26-29; HFSR bits 0,2-29.
        result = self.analyze(base_request(cfsr=0x3CF0_4044, hfsr=0x3FFF_FFFD))
        self.assertEqual(result["causes"], [])
        self.assertEqual(result["status"]["cfsr"], 0x3CF0_4044)
        self.assertEqual(result["status"]["hfsr"], 0x3FFF_FFFD)

    def test_valid_bits_are_not_causes(self):
        result = self.analyze(base_request(cfsr=(1 << 7) | (1 << 15)))
        self.assertEqual(result["causes"], [])

    def test_primary_priority_order(self):
        result = self.analyze(base_request(cfsr=1 << 25, hfsr=1 << 30))
        self.assertEqual(result["primary"], "usagefault")

        result = self.analyze(base_request(cfsr=1 << 9))
        self.assertEqual(result["primary"], "busfault")

        result = self.analyze(base_request(cfsr=1 << 0))
        self.assertEqual(result["primary"], "memmanage")

        result = self.analyze(base_request(hfsr=1 << 31))
        self.assertEqual(result["primary"], "hardfault")

        result = self.analyze(base_request())
        self.assertEqual(result["primary"], "none")

    def test_fault_addresses_gated_by_valid_bits(self):
        result = self.analyze(base_request(cfsr=(1 << 7) | (1 << 15)))
        self.assertEqual(
            result["fault_addresses"],
            {"mmfar": 0x2000_0000, "bfar": 0x2000_1000},
        )

        result = self.analyze(base_request(cfsr=1 << 7))
        self.assertEqual(result["fault_addresses"]["mmfar"], 0x2000_0000)
        self.assertIsNone(result["fault_addresses"]["bfar"])

        result = self.analyze(base_request(cfsr=1 << 15))
        self.assertIsNone(result["fault_addresses"]["mmfar"])
        self.assertEqual(result["fault_addresses"]["bfar"], 0x2000_1000)

        result = self.analyze(base_request(cfsr=0))
        self.assertEqual(result["fault_addresses"], {"mmfar": None, "bfar": None})

    # --- validation -----------------------------------------------------

    def assert_invalid_request(self, body):
        from probepoint.faults import FaultError

        with self.assertRaises(FaultError) as ctx:
            self.analyze(body)
        self.assertEqual(ctx.exception.code, "invalid_request")

    def assert_invalid_field(self, body):
        from probepoint.faults import FaultError

        with self.assertRaises(FaultError) as ctx:
            self.analyze(body)
        self.assertEqual(ctx.exception.code, "invalid_field")

    def test_body_must_be_object(self):
        for body in (None, [], "x", 1, True):
            with self.subTest(body=body):
                self.assert_invalid_request(body)

    def test_missing_and_extra_fields(self):
        self.assert_invalid_field({})
        self.assert_invalid_field({"stacked_frame": encode_frame(VALID_WORDS)})
        self.assert_invalid_field({**base_request(), "extra": 1})
        self.assert_invalid_field(
            {"stacked_frame": encode_frame(VALID_WORDS), "cfsr": 0, "hfsr": 0}
        )

    def test_uint32_fields_validation(self):
        for field in ("cfsr", "hfsr", "mmfar", "bfar"):
            for value in (-1, 1 << 32, 1.5, "1", True, False, None, []):
                with self.subTest(field=field, value=value):
                    self.assert_invalid_field(base_request(**{field: value}))
        # Boundary values are accepted.
        self.analyze(base_request(cfsr=0, hfsr=U32_MAX, mmfar=U32_MAX, bfar=0))

    def test_stacked_frame_type_and_hex(self):
        for value in (0, 1234, True, None, [], b""):
            with self.subTest(value=value):
                self.assert_invalid_field(base_request(stacked_frame=value))
        # Odd length, non-hex characters and prefixes are illegal.
        self.assert_invalid_field(base_request(stacked_frame="0" * 63))
        self.assert_invalid_field(base_request(stacked_frame="zz" * 32))
        self.assert_invalid_field(base_request(stacked_frame="0x" + "00" * 32))

    def test_stacked_frame_length_must_be_exactly_32_bytes(self):
        self.assert_invalid_field(base_request(stacked_frame=""))
        self.assert_invalid_field(base_request(stacked_frame="00" * 31))
        self.assert_invalid_field(base_request(stacked_frame="00" * 33))
        self.analyze(base_request(stacked_frame="ff" * 32))


class AnalyzeCortexMFaultHttpTest(unittest.TestCase):
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

    def request(self, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{PATH}",
            data=data,
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

    def raw_request(self, raw):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{PATH}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read()
            finally:
                exc.close()

    def test_success_over_http(self):
        status, body = self.request(
            base_request(cfsr=(1 << 1) | (1 << 7) | (1 << 30), hfsr=1 << 30)
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["primary"], "memmanage")
        self.assertEqual([c["name"] for c in body["causes"]], ["DACCVIOL", "FORCED"])
        self.assertEqual(body["fault_addresses"]["mmfar"], 0x2000_0000)
        self.assertIsNone(body["fault_addresses"]["bfar"])
        self.assertTrue(body["frame"]["frame_valid"])

    def test_invalid_json_is_invalid_request(self):
        status, raw = self.raw_request(b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_json_non_object_is_invalid_request(self):
        status, raw = self.raw_request(b"null")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_invalid_field_over_http(self):
        status, body = self.request(base_request(stacked_frame="00" * 16))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_bool_integer_rejected_over_http(self):
        status, body = self.request(base_request(cfsr=True))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_no_partial_results(self):
        bad = base_request()
        del bad["bfar"]
        status, body = self.request(bad)
        self.assertEqual(status, 400)
        self.assertEqual(set(body), {"error"})


if __name__ == "__main__":
    unittest.main()
