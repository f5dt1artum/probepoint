import json
import struct
import threading
import unittest
import urllib.error
import urllib.request

from probepoint.faults import FaultError, analyze_cortex_m_fault
from probepoint.server import make_server

PATH = "/v1/faults/cortex-m/analyze"
U32_MAX = 0xFFFFFFFF


def frame_hex(words):
    return struct.pack("<8I", *words).hex()


VALID_FRAME = frame_hex(
    [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x08001235, 0x21000000]
)


def request_body(**overrides):
    body = {
        "stacked_frame": VALID_FRAME,
        "cfsr": 0,
        "hfsr": 0,
        "mmfar": 0,
        "bfar": 0,
    }
    body.update(overrides)
    return body


class AnalyzeCortexMFaultTest(unittest.TestCase):
    def analyze(self, body):
        return analyze_cortex_m_fault(body)

    # --- frame ----------------------------------------------------------

    def test_frame_registers_little_endian(self):
        result = self.analyze(request_body())
        frame = result["frame"]
        self.assertEqual(
            {k: frame[k] for k in ("r0", "r1", "r2", "r3", "r12", "lr", "pc", "xpsr")},
            {
                "r0": 0x11111111,
                "r1": 0x22222222,
                "r2": 0x33333333,
                "r3": 0x44444444,
                "r12": 0x55555555,
                "lr": 0x66666666,
                "pc": 0x08001235,
                "xpsr": 0x21000000,
            },
        )

    def test_instruction_address_clears_thumb_bit(self):
        result = self.analyze(request_body())
        self.assertEqual(result["frame"]["instruction_address"], 0x08001234)
        self.assertTrue(result["frame"]["frame_valid"])

    def test_instruction_address_when_bit_already_clear(self):
        words = [0, 0, 0, 0, 0, 0, 0x08002000, 0x21000000]
        result = self.analyze(request_body(stacked_frame=frame_hex(words)))
        self.assertEqual(result["frame"]["instruction_address"], 0x08002000)

    def test_frame_invalid_when_t_bit_clear_but_still_reported(self):
        # xpsr=0x20000000 keeps the N flag but has the T bit (bit 24) clear.
        words = [0, 0, 0, 0, 0, 0, 0x08001234, 0x20000000]
        result = self.analyze(request_body(stacked_frame=frame_hex(words)))
        self.assertFalse(result["frame"]["frame_valid"])
        self.assertEqual(result["frame"]["instruction_address"], 0x08001234)

    def test_frame_has_exactly_ten_fields(self):
        result = self.analyze(request_body())
        self.assertEqual(
            set(result["frame"]),
            {"r0", "r1", "r2", "r3", "r12", "lr", "pc", "xpsr", "instruction_address", "frame_valid"},
        )

    def test_uppercase_hex_accepted(self):
        result = self.analyze(request_body(stacked_frame=VALID_FRAME.upper()))
        self.assertEqual(result["frame"]["r0"], 0x11111111)

    # --- status ---------------------------------------------------------

    def test_status_echoes_registers_verbatim(self):
        result = self.analyze(request_body(cfsr=0xDEADBEEF, hfsr=0xCAFEBABE))
        self.assertEqual(result["status"], {"cfsr": 0xDEADBEEF, "hfsr": 0xCAFEBABE})

    # --- causes --------------------------------------------------------

    def test_no_causes(self):
        result = self.analyze(request_body())
        self.assertEqual(result["causes"], [])
        self.assertEqual(result["primary"], "none")

    def test_each_named_cfsr_bit_recognized(self):
        expected = [
            (0, "IACCVIOL"),
            (1, "DACCVIOL"),
            (3, "MUNSTKERR"),
            (4, "MSTKERR"),
            (5, "MLSPERR"),
            (8, "IBUSERR"),
            (9, "PRECISERR"),
            (10, "IMPRECISERR"),
            (11, "UNSTKERR"),
            (12, "STKERR"),
            (13, "LSPERR"),
            (16, "UNDEFINSTR"),
            (17, "INVSTATE"),
            (18, "INVPC"),
            (19, "NOCP"),
            (24, "UNALIGNED"),
            (25, "DIVBYZERO"),
        ]
        for bit, name in expected:
            with self.subTest(bit=bit, name=name):
                result = self.analyze(request_body(cfsr=1 << bit))
                self.assertEqual(
                    result["causes"], [{"register": "cfsr", "bit": bit, "name": name}]
                )

    def test_named_hfsr_bits(self):
        for bit, name in ((30, "FORCED"), (31, "DEBUGEVT")):
            with self.subTest(bit=bit, name=name):
                result = self.analyze(request_body(hfsr=1 << bit))
                self.assertEqual(
                    result["causes"], [{"register": "hfsr", "bit": bit, "name": name}]
                )
                self.assertEqual(result["primary"], "hardfault")

    def test_causes_ordered_cfsr_then_hfsr_by_bit(self):
        cfsr = (1 << 25) | (1 << 1) | (1 << 16) | (1 << 8) | (1 << 0)
        hfsr = (1 << 31) | (1 << 30)
        result = self.analyze(request_body(cfsr=cfsr, hfsr=hfsr))
        self.assertEqual(
            [(c["register"], c["bit"], c["name"]) for c in result["causes"]],
            [
                ("cfsr", 0, "IACCVIOL"),
                ("cfsr", 1, "DACCVIOL"),
                ("cfsr", 8, "IBUSERR"),
                ("cfsr", 16, "UNDEFINSTR"),
                ("cfsr", 25, "DIVBYZERO"),
                ("hfsr", 30, "FORCED"),
                ("hfsr", 31, "DEBUGEVT"),
            ],
        )

    def test_undefined_bits_remain_in_status_but_not_causes(self):
        # CFSR undefined/valid bits: 2, 6, 7 (MMARVALID), 14, 15 (BFARVALID),
        # 20-23, 26-31; HFSR undefined bits 0-29.
        cfsr = (1 << 2) | (1 << 6) | (1 << 7) | (1 << 14) | (1 << 15)
        cfsr |= (1 << 20) | (1 << 26) | (1 << 31)
        hfsr = (1 << 0) | (1 << 29)
        result = self.analyze(request_body(cfsr=cfsr, hfsr=hfsr))
        self.assertEqual(result["status"]["cfsr"], cfsr)
        self.assertEqual(result["status"]["hfsr"], hfsr)
        self.assertEqual(result["causes"], [])
        self.assertEqual(result["primary"], "none")

    def test_cause_entries_have_exactly_three_fields(self):
        result = self.analyze(request_body(cfsr=1 << 0, hfsr=1 << 30))
        for cause in result["causes"]:
            self.assertEqual(set(cause), {"register", "bit", "name"})

    # --- primary --------------------------------------------------------

    def test_primary_precedence(self):
        cases = [
            (1 << 0, "memmanage"),
            (1 << 5, "memmanage"),
            (1 << 8, "busfault"),
            (1 << 16, "usagefault"),
            (1 << 25, "usagefault"),
        ]
        for cfsr, primary in cases:
            with self.subTest(cfsr=cfsr):
                self.assertEqual(self.analyze(request_body(cfsr=cfsr))["primary"], primary)

    def test_primary_memmanage_wins_over_bus_usage_hard(self):
        result = self.analyze(
            request_body(cfsr=(1 << 4) | (1 << 9) | (1 << 19), hfsr=1 << 30)
        )
        self.assertEqual(result["primary"], "memmanage")

    def test_primary_busfault_wins_over_usage_and_hard(self):
        result = self.analyze(request_body(cfsr=(1 << 12) | (1 << 24), hfsr=1 << 30))
        self.assertEqual(result["primary"], "busfault")

    def test_primary_usagefault_wins_over_hard(self):
        result = self.analyze(request_body(cfsr=1 << 17, hfsr=1 << 30))
        self.assertEqual(result["primary"], "usagefault")

    # --- fault addresses ------------------------------------------------

    def test_fault_addresses_null_without_valid_bits(self):
        result = self.analyze(request_body(mmfar=0x20000000, bfar=0x20001000, cfsr=1 << 9))
        self.assertEqual(result["fault_addresses"], {"mmfar": None, "bfar": None})

    def test_mmfar_returned_only_with_mmarvalid(self):
        result = self.analyze(
            request_body(mmfar=0x20000004, bfar=0x20001000, cfsr=1 << 7)
        )
        self.assertEqual(result["fault_addresses"]["mmfar"], 0x20000004)
        self.assertIsNone(result["fault_addresses"]["bfar"])
        # The valid bit is not itself a cause.
        self.assertEqual(result["causes"], [])

    def test_bfar_returned_only_with_bfarvalid(self):
        result = self.analyze(
            request_body(mmfar=0x20000004, bfar=0x20001008, cfsr=1 << 15)
        )
        self.assertIsNone(result["fault_addresses"]["mmfar"])
        self.assertEqual(result["fault_addresses"]["bfar"], 0x20001008)
        self.assertEqual(result["causes"], [])

    def test_both_valid_bits(self):
        result = self.analyze(
            request_body(
                mmfar=0x10,
                bfar=0x20,
                cfsr=(1 << 7) | (1 << 15) | (1 << 1),
            )
        )
        self.assertEqual(result["fault_addresses"], {"mmfar": 0x10, "bfar": 0x20})
        self.assertEqual([c["name"] for c in result["causes"]], ["DACCVIOL"])

    def test_fault_addresses_always_present(self):
        result = self.analyze(request_body())
        self.assertEqual(set(result["fault_addresses"]), {"mmfar", "bfar"})

    # --- validation -----------------------------------------------------

    def assert_invalid_request(self, body):
        with self.assertRaises(FaultError) as ctx:
            self.analyze(body)
        self.assertEqual(ctx.exception.code, "invalid_request")

    def assert_invalid_field(self, body):
        with self.assertRaises(FaultError) as ctx:
            self.analyze(body)
        self.assertEqual(ctx.exception.code, "invalid_field")

    def test_body_must_be_object(self):
        for body in (None, [], "x", 1, True):
            with self.subTest(body=body):
                self.assert_invalid_request(body)

    def test_missing_and_extra_fields(self):
        base = request_body()
        for field in base:
            partial = {k: v for k, v in base.items() if k != field}
            with self.subTest(missing=field):
                self.assert_invalid_field(partial)
        self.assert_invalid_field({})
        self.assert_invalid_field({**base, "extra": 1})

    def test_u32_fields_reject_bad_types_and_range(self):
        for field in ("cfsr", "hfsr", "mmfar", "bfar"):
            for value in (-1, 1 << 32, 1.0, "1", True, False, None, []):
                with self.subTest(field=field, value=value):
                    self.assert_invalid_field(request_body(**{field: value}))
            # Boundary values are accepted.
            self.analyze(request_body(**{field: 0}))
            self.analyze(request_body(**{field: U32_MAX}))

    def test_stacked_frame_type(self):
        for value in (None, 1, 1.5, True, [], b""):
            with self.subTest(value=value):
                self.assert_invalid_field(request_body(stacked_frame=value))

    def test_stacked_frame_illegal_hex(self):
        for value in ("", "abc", "0x" + "00" * 32, "zz" * 32, VALID_FRAME[:-1]):
            with self.subTest(value=value[:12]):
                self.assert_invalid_field(request_body(stacked_frame=value))

    def test_stacked_frame_wrong_length(self):
        # Odd-length is illegal hex; even but wrong byte counts are length errors.
        self.assert_invalid_field(request_body(stacked_frame="00" * 30))
        self.assert_invalid_field(request_body(stacked_frame="00" * 34))
        self.assert_invalid_field(request_body(stacked_frame="00" * 31))
        self.assert_invalid_field(request_body(stacked_frame="00" * 33))

    def test_success_shape(self):
        result = self.analyze(request_body())
        self.assertEqual(set(result), {"frame", "status", "primary", "causes", "fault_addresses"})
        self.assertEqual(set(result["status"]), {"cfsr", "hfsr"})


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
            request_body(
                cfsr=(1 << 1) | (1 << 7) | (1 << 30),
                hfsr=1 << 30,
                mmfar=0x20000010,
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["primary"], "memmanage")
        self.assertEqual(
            [c["name"] for c in body["causes"]], ["DACCVIOL", "FORCED"]
        )
        self.assertEqual(body["fault_addresses"]["mmfar"], 0x20000010)
        self.assertIsNone(body["fault_addresses"]["bfar"])
        self.assertEqual(body["frame"]["instruction_address"], 0x08001234)
        self.assertTrue(body["frame"]["frame_valid"])

    def test_invalid_json_is_invalid_request(self):
        status, raw = self.raw_request(b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_json_non_object_is_invalid_request(self):
        status, raw = self.raw_request(b"[1, 2]")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_invalid_field_over_http(self):
        status, body = self.request(request_body(cfsr=True))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_bad_frame_length_over_http(self):
        status, body = self.request(request_body(stacked_frame="00" * 16))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_missing_field_over_http(self):
        partial = request_body()
        del partial["bfar"]
        status, body = self.request(partial)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_no_partial_results(self):
        status, body = self.request({**request_body(), "cfsr": "nope", "hfsr": -1})
        self.assertEqual(status, 400)
        self.assertEqual(set(body), {"error"})

    def test_unknown_route_unchanged(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/faults/cortex-m",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                status, payload = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, exc.read()
            exc.close()
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(payload)["error"]["code"], "not_found")

    def test_existing_performance_entry_still_works(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/performance/cycles/analyze",
            data=json.dumps(
                {"clock_hz": 1, "samples": [{"label": "a", "start": 0, "end": 1}]}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            status, payload = resp.status, json.loads(resp.read())
        self.assertEqual(status, 200)
        self.assertEqual(payload["samples"][0]["cycles"], 1)


if __name__ == "__main__":
    unittest.main()
