import json
import threading
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server

PATH = "/v1/performance/cycles/analyze"
U32_MAX = 0xFFFFFFFF


class CyclesAnalyzeHttpTest(unittest.TestCase):
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

    def post_raw(self, path: str, raw: bytes) -> tuple[int, bytes]:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
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

    def analyze(self, body: object) -> tuple[int, object]:
        status, raw = self.post_raw(PATH, json.dumps(body).encode("utf-8"))
        return status, json.loads(raw)

    def analyze_raw(self, raw: bytes) -> tuple[int, object]:
        status, data = self.post_raw(PATH, raw)
        return status, json.loads(data)

    def test_basic_no_wrap(self) -> None:
        status, payload = self.analyze(
            {
                "clock_hz": 100,
                "samples": [
                    {"label": "a", "start": 10, "end": 110},
                    {"label": "a", "start": 0, "end": 3},
                    {"label": "b", "start": 5, "end": 5},
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["samples"],
            [
                {
                    "label": "a",
                    "start": 10,
                    "end": 110,
                    "cycles": 100,
                    "wrapped": False,
                    "duration_ns": 1_000_000_000,
                },
                {
                    "label": "a",
                    "start": 0,
                    "end": 3,
                    "cycles": 3,
                    "wrapped": False,
                    "duration_ns": 30_000_000,
                },
                {
                    "label": "b",
                    "start": 5,
                    "end": 5,
                    "cycles": 0,
                    "wrapped": False,
                    "duration_ns": 0,
                },
            ],
        )
        self.assertEqual(
            payload["summary"],
            [
                {
                    "label": "a",
                    "count": 2,
                    "total_cycles": 103,
                    "min_cycles": 3,
                    "max_cycles": 100,
                    "average_cycles": 51,
                    "total_duration_ns": 1_030_000_000,
                    "average_duration_ns": 515_000_000,
                },
                {
                    "label": "b",
                    "count": 1,
                    "total_cycles": 0,
                    "min_cycles": 0,
                    "max_cycles": 0,
                    "average_cycles": 0,
                    "total_duration_ns": 0,
                    "average_duration_ns": 0,
                },
            ],
        )

    def test_wrap(self) -> None:
        status, payload = self.analyze(
            {
                "clock_hz": 1_000_000_000,
                "samples": [
                    {"label": "w", "start": U32_MAX - 1, "end": 3},
                    {"label": "w", "start": U32_MAX, "end": 0},
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["samples"][0]["cycles"], 5)
        self.assertIs(payload["samples"][0]["wrapped"], True)
        self.assertEqual(payload["samples"][0]["duration_ns"], 5)
        self.assertEqual(payload["samples"][1]["cycles"], 1)
        self.assertIs(payload["samples"][1]["wrapped"], True)
        summary = payload["summary"][0]
        self.assertEqual(summary["total_cycles"], 6)
        self.assertEqual(summary["min_cycles"], 1)
        self.assertEqual(summary["max_cycles"], 5)
        self.assertEqual(summary["average_cycles"], 3)
        self.assertEqual(summary["total_duration_ns"], 6)
        self.assertEqual(summary["average_duration_ns"], 3)

    def test_duration_floors(self) -> None:
        # 3 cycles at 10 Hz -> 300_000_000 ns each; totals/average floor.
        status, payload = self.analyze(
            {
                "clock_hz": 7,
                "samples": [
                    {"label": "x", "start": 0, "end": 1},
                    {"label": "x", "start": 0, "end": 2},
                ],
            }
        )
        self.assertEqual(status, 200)
        # floor(1e9 / 7) = 142857142, floor(2e9 / 7) = 285714285
        self.assertEqual(payload["samples"][0]["duration_ns"], 142_857_142)
        self.assertEqual(payload["samples"][1]["duration_ns"], 285_714_285)
        summary = payload["summary"][0]
        # total_duration_ns is the sum of per-sample durations, not a
        # fresh floor over total cycles.
        self.assertEqual(summary["total_duration_ns"], 428_571_427)
        self.assertEqual(summary["average_cycles"], 1)
        self.assertEqual(summary["average_duration_ns"], 214_285_713)

    def test_label_normalization_and_first_occurrence_order(self) -> None:
        status, payload = self.analyze(
            {
                "clock_hz": 10,
                "samples": [
                    {"label": "  b\t", "start": 0, "end": 1},
                    {"label": "a", "start": 0, "end": 1},
                    {"label": "　b　", "start": 0, "end": 1},
                ],
            }
        )
        self.assertEqual(status, 200)
        labels = [s["label"] for s in payload["samples"]]
        self.assertEqual(labels, ["b", "a", "b"])
        self.assertEqual([s["label"] for s in payload["summary"]], ["b", "a"])
        self.assertEqual(payload["summary"][0]["count"], 2)
        self.assertEqual(payload["summary"][1]["count"], 1)

    def test_all_numbers_serialize_as_integers(self) -> None:
        body = {
            "clock_hz": 3,
            "samples": [{"label": "z", "start": 0, "end": U32_MAX}],
        }
        status, raw = self.post_raw(PATH, json.dumps(body).encode("utf-8"))
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        # parse_float only fires for wire tokens containing "." or an exponent,
        # so an empty list proves every number is a plain integer literal.
        float_tokens: list[str] = []
        parsed = json.loads(text, parse_float=lambda token: float_tokens.append(token))
        self.assertEqual(float_tokens, [])
        duration = parsed["samples"][0]["duration_ns"]
        self.assertIsInstance(duration, int)
        self.assertEqual(duration, (U32_MAX * 1_000_000_000) // 3)

    def test_extreme_values(self) -> None:
        status, payload = self.analyze(
            {
                "clock_hz": 1,
                "samples": [
                    {"label": "max", "start": 0, "end": U32_MAX},
                    {"label": "wrap", "start": 1, "end": 0},
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["samples"][0]["cycles"], U32_MAX)
        self.assertEqual(payload["samples"][0]["duration_ns"], U32_MAX * 1_000_000_000)
        self.assertEqual(payload["samples"][1]["cycles"], (1 << 32) - 1)
        self.assertIs(payload["samples"][1]["wrapped"], True)

    # --- error cases -----------------------------------------------------

    def assert_invalid_request(self, status: int, payload: object) -> None:
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def assert_invalid_field(self, status: int, payload: object) -> None:
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_field")

    def test_malformed_json(self) -> None:
        status, payload = self.analyze_raw(b"{not json")
        self.assert_invalid_request(status, payload)

    def test_non_object_body(self) -> None:
        for raw in (b"[1,2]", b"null", b'"x"', b"42", b"true"):
            with self.subTest(raw=raw):
                status, payload = self.analyze_raw(raw)
                self.assert_invalid_request(status, payload)

    def test_missing_and_extra_top_level_fields(self) -> None:
        status, payload = self.analyze({"samples": []})
        self.assert_invalid_field(status, payload)
        status, payload = self.analyze({"clock_hz": 1})
        self.assert_invalid_field(status, payload)
        status, payload = self.analyze(
            {"clock_hz": 1, "samples": [], "extra": 1}
        )
        self.assert_invalid_field(status, payload)

    def test_clock_hz_validation(self) -> None:
        good = {"label": "a", "start": 0, "end": 1}
        for value in (0, 2**32, -1, 1.5, "8", None, True, False, []):
            with self.subTest(value=value):
                status, payload = self.analyze({"clock_hz": value, "samples": [good]})
                self.assert_invalid_field(status, payload)

    def test_samples_count_bounds(self) -> None:
        status, payload = self.analyze({"clock_hz": 1, "samples": []})
        self.assert_invalid_field(status, payload)
        sample = {"label": "a", "start": 0, "end": 1}
        status, payload = self.analyze(
            {"clock_hz": 1, "samples": [sample] * 4097}
        )
        self.assert_invalid_field(status, payload)
        status, payload = self.analyze(
            {"clock_hz": 1, "samples": [sample] * 4096}
        )
        self.assertEqual(status, 200)

    def test_sample_field_errors(self) -> None:
        base = {"clock_hz": 1}
        bad_bodies = [
            {"samples": [{"label": "a", "start": 0}]},  # missing end
            {"samples": [{"label": "a", "start": 0, "end": 1, "x": 2}]},  # extra
            {"samples": [{"label": 1, "start": 0, "end": 1}]},  # label type
            {"samples": [{"label": "  \t", "start": 0, "end": 1}]},  # blank label
            {"samples": [{"label": "x" * 65, "start": 0, "end": 1}]},  # long label
            {"samples": [{"label": "a", "start": -1, "end": 1}]},  # negative
            {"samples": [{"label": "a", "start": 0, "end": 2**32}]},  # too big
            {"samples": [{"label": "a", "start": True, "end": 1}]},  # bool
            {"samples": [{"label": "a", "start": 0, "end": 1.0}]},  # float
            {"samples": [{"label": "a", "start": "0", "end": 1}]},  # string
            {"samples": ["nope"]},  # not an object
        ]
        for body in bad_bodies:
            with self.subTest(body=body):
                status, payload = self.analyze({**base, **body})
                self.assert_invalid_field(status, payload)

    def test_samples_not_array(self) -> None:
        for value in ({}, "x", 1, None, True):
            with self.subTest(value=value):
                status, payload = self.analyze({"clock_hz": 1, "samples": value})
                self.assert_invalid_field(status, payload)

    def test_no_partial_results_on_late_error(self) -> None:
        status, payload = self.analyze(
            {
                "clock_hz": 1,
                "samples": [
                    {"label": "ok", "start": 0, "end": 10},
                    {"label": "bad", "start": 0, "end": 2**33},
                ],
            }
        )
        self.assert_invalid_field(status, payload)
        self.assertNotIn("samples", payload)
        self.assertNotIn("summary", payload)

    def test_adjacent_path_is_not_routed(self) -> None:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/performance/cycles",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)
        self.assertEqual(json.loads(ctx.exception.read())["error"]["code"], "not_found")
        ctx.exception.close()


if __name__ == "__main__":
    unittest.main()
