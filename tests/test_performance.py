import json
import threading
import unittest
import urllib.error
import urllib.request

from probepoint.performance import analyze_cycles
from probepoint.server import make_server

PATH = "/v1/performance/cycles/analyze"
U32_MAX = 0xFFFFFFFF


class AnalyzeCyclesTest(unittest.TestCase):
    def analyze(self, body):
        return analyze_cycles(body)

    def test_simple_no_wrap_integer_duration(self):
        result = self.analyze(
            {"clock_hz": 1_000_000, "samples": [{"label": "isr", "start": 100, "end": 1100}]}
        )
        (sample,) = result["samples"]
        self.assertEqual(
            sample,
            {
                "label": "isr",
                "start": 100,
                "end": 1100,
                "cycles": 1000,
                "wrapped": False,
                "duration_ns": 1_000_000,
            },
        )
        (summary,) = result["summary"]
        self.assertEqual(
            summary,
            {
                "label": "isr",
                "count": 1,
                "total_cycles": 1000,
                "min_cycles": 1000,
                "max_cycles": 1000,
                "average_cycles": 1000,
                "total_duration_ns": 1_000_000,
                "average_duration_ns": 1_000_000,
            },
        )

    def test_duration_is_floored_not_rounded(self):
        # 3 cycles at 10 MHz = 300 ns exactly; 1 cycle at 3 Hz floors to 333333333 ns.
        result = self.analyze(
            {"clock_hz": 3, "samples": [{"label": "a", "start": 0, "end": 1}]}
        )
        self.assertEqual(result["samples"][0]["duration_ns"], 333_333_333)

    def test_equal_start_end_is_zero_cycles_no_wrap(self):
        result = self.analyze(
            {"clock_hz": 1, "samples": [{"label": "a", "start": 42, "end": 42}]}
        )
        sample = result["samples"][0]
        self.assertEqual(sample["cycles"], 0)
        self.assertFalse(sample["wrapped"])
        self.assertEqual(sample["duration_ns"], 0)

    def test_single_wrap(self):
        result = self.analyze(
            {
                "clock_hz": 80_000_000,
                "samples": [
                    {"label": "w", "start": 0xFFFFFFF0, "end": 0x20}
                ],
            }
        )
        sample = result["samples"][0]
        self.assertEqual(sample["cycles"], 0x30)
        self.assertTrue(sample["wrapped"])
        self.assertEqual(sample["duration_ns"], (0x30 * 1_000_000_000) // 80_000_000)

    def test_wrap_across_full_range(self):
        # start=1, end=0 => 2^32 - 1 cycles.
        result = self.analyze(
            {"clock_hz": U32_MAX, "samples": [{"label": "w", "start": 1, "end": 0}]}
        )
        sample = result["samples"][0]
        self.assertEqual(sample["cycles"], U32_MAX)
        self.assertTrue(sample["wrapped"])
        self.assertEqual(sample["duration_ns"], (sample["cycles"] * 1_000_000_000) // U32_MAX)

    def test_label_normalization_preserves_duplicates_in_input_order(self):
        body = {
            "clock_hz": 100,
            "samples": [
                {"label": "  isr  ", "start": 0, "end": 10},
                {"label": "other", "start": 0, "end": 5},
                {"label": "\t isr\n", "start": 0, "end": 7},
            ],
        }
        result = self.analyze(body)
        self.assertEqual([s["label"] for s in result["samples"]], ["isr", "other", "isr"])
        self.assertEqual([s["cycles"] for s in result["samples"]], [10, 5, 7])
        # Summary ordered by first appearance, not sorted.
        self.assertEqual([s["label"] for s in result["summary"]], ["isr", "other"])

    def test_summary_aggregation_and_floored_averages(self):
        result = self.analyze(
            {
                "clock_hz": 7,
                "samples": [
                    {"label": "a", "start": 0, "end": 10},
                    {"label": "a", "start": 0, "end": 11},
                    {"label": "a", "start": 0, "end": 12},
                ],
            }
        )
        (summary,) = result["summary"]
        self.assertEqual(summary["count"], 3)
        self.assertEqual(summary["total_cycles"], 33)
        self.assertEqual(summary["min_cycles"], 10)
        self.assertEqual(summary["max_cycles"], 12)
        self.assertEqual(summary["average_cycles"], 11)
        durations = [10 * 1_000_000_000 // 7, 11 * 1_000_000_000 // 7, 12 * 1_000_000_000 // 7]
        self.assertEqual([s["duration_ns"] for s in result["samples"]], durations)
        # total_duration_ns is the sum of per-item floors, not floor(total cycles).
        self.assertEqual(summary["total_duration_ns"], sum(durations))
        self.assertNotEqual(summary["total_duration_ns"], summary["total_cycles"] * 1_000_000_000 // 7)
        self.assertEqual(summary["average_duration_ns"], sum(durations) // 3)

    def test_duplicate_normalized_labels_aggregate_together(self):
        result = self.analyze(
            {
                "clock_hz": 1,
                "samples": [
                    {"label": "x", "start": 0, "end": 1},
                    {"label": "x ", "start": 0, "end": 2},
                ],
            }
        )
        self.assertEqual(len(result["summary"]), 1)
        self.assertEqual(result["summary"][0]["count"], 2)
        self.assertEqual(result["summary"][0]["total_cycles"], 3)

    def test_large_values_stay_integers(self):
        result = self.analyze(
            {
                "clock_hz": 1,
                "samples": [{"label": "big", "start": 0, "end": U32_MAX}],
            }
        )
        sample = result["samples"][0]
        self.assertEqual(sample["cycles"], U32_MAX)
        self.assertEqual(sample["duration_ns"], U32_MAX * 1_000_000_000)
        for value in sample.values():
            if isinstance(value, int):
                self.assertNotIsInstance(value, float)

    def test_max_sample_count(self):
        body = {
            "clock_hz": 1,
            "samples": [{"label": "a", "start": 0, "end": 1}] * 4096,
        }
        result = self.analyze(body)
        self.assertEqual(len(result["samples"]), 4096)
        self.assertEqual(result["summary"][0]["count"], 4096)

    # --- validation -----------------------------------------------------

    def assert_invalid_request(self, body):
        from probepoint.performance import PerformanceError

        with self.assertRaises(PerformanceError) as ctx:
            self.analyze(body)
        self.assertEqual(ctx.exception.code, "invalid_request")

    def assert_invalid_field(self, body):
        from probepoint.performance import PerformanceError

        with self.assertRaises(PerformanceError) as ctx:
            self.analyze(body)
        self.assertEqual(ctx.exception.code, "invalid_field")

    def test_body_must_be_object(self):
        for body in (None, [], "x", 1, True):
            with self.subTest(body=body):
                self.assert_invalid_request(body)

    def test_missing_and_extra_fields(self):
        self.assert_invalid_field({"clock_hz": 1})
        self.assert_invalid_field({"samples": []})
        self.assert_invalid_field({})
        self.assert_invalid_field(
            {"clock_hz": 1, "samples": [], "extra": 1}
        )

    def test_sample_missing_and_extra_fields(self):
        base = {"clock_hz": 1}
        self.assert_invalid_field({**base, "samples": [{"start": 0, "end": 1}]})
        self.assert_invalid_field({**base, "samples": [{"label": "a", "end": 1}]})
        self.assert_invalid_field({**base, "samples": [{"label": "a", "start": 0}]})
        self.assert_invalid_field(
            {**base, "samples": [{"label": "a", "start": 0, "end": 1, "x": 2}]}
        )

    def test_clock_hz_validation(self):
        for value in (0, -1, 1 << 32, 1.5, "8", True, None, []):
            with self.subTest(value=value):
                self.assert_invalid_field(
                    {"clock_hz": value, "samples": [{"label": "a", "start": 0, "end": 1}]}
                )
        # Boundary values are accepted.
        self.analyze(
            {"clock_hz": U32_MAX, "samples": [{"label": "a", "start": 0, "end": 1}]}
        )
        self.analyze(
            {"clock_hz": 1, "samples": [{"label": "a", "start": 0, "end": 1}]}
        )

    def test_start_end_validation(self):
        for value in (-1, 1 << 32, 1.0, "1", True, None):
            with self.subTest(value=value):
                self.assert_invalid_field(
                    {
                        "clock_hz": 1,
                        "samples": [{"label": "a", "start": value, "end": 1}],
                    }
                )
                self.assert_invalid_field(
                    {
                        "clock_hz": 1,
                        "samples": [{"label": "a", "start": 0, "end": value}],
                    }
                )

    def test_samples_count_validation(self):
        self.assert_invalid_field({"clock_hz": 1, "samples": []})
        self.assert_invalid_field(
            {"clock_hz": 1, "samples": [{"label": "a", "start": 0, "end": 1}] * 4097}
        )
        self.assert_invalid_field({"clock_hz": 1, "samples": "no"})

    def test_samples_entries_must_be_objects(self):
        self.assert_invalid_field(
            {"clock_hz": 1, "samples": [{"label": "a", "start": 0, "end": 1}, None]}
        )

    def test_label_validation(self):
        for label in ("", "   ", "\t\n  ", 1, True, None, ["a"]):
            with self.subTest(label=repr(label)):
                self.assert_invalid_field(
                    {
                        "clock_hz": 1,
                        "samples": [{"label": label, "start": 0, "end": 1}],
                    }
                )
        self.assert_invalid_field(
            {
                "clock_hz": 1,
                "samples": [{"label": "a" * 65, "start": 0, "end": 1}],
            }
        )
        # 64 chars after stripping is accepted.
        result = self.analyze(
            {
                "clock_hz": 1,
                "samples": [{"label": " " + "a" * 64 + " ", "start": 0, "end": 1}],
            }
        )
        self.assertEqual(result["samples"][0]["label"], "a" * 64)


class AnalyzeCyclesHttpTest(unittest.TestCase):
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
            {
                "clock_hz": 1_000_000,
                "samples": [
                    {"label": "a", "start": 0, "end": 1000},
                    {"label": "a", "start": 0xFFFFFFF0, "end": 0x10},
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["samples"][0]["cycles"], 1000)
        self.assertFalse(body["samples"][0]["wrapped"])
        self.assertEqual(body["samples"][0]["duration_ns"], 1_000_000)
        self.assertEqual(body["samples"][1]["cycles"], 0x20)
        self.assertTrue(body["samples"][1]["wrapped"])
        self.assertEqual(body["summary"][0]["count"], 2)

    def test_invalid_json_is_invalid_request(self):
        status, raw = self.raw_request(b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_json_non_object_is_invalid_request(self):
        status, raw = self.raw_request(b"[1, 2]")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_invalid_field_over_http(self):
        status, body = self.request({"clock_hz": 0, "samples": []})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_bool_clock_rejected(self):
        status, body = self.request(
            {"clock_hz": True, "samples": [{"label": "a", "start": 0, "end": 1}]}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_no_partial_results_on_late_failure(self):
        samples = [{"label": "a", "start": 0, "end": 1}] * 4096
        samples.append({"label": "a", "start": 0, "end": 1})
        status, body = self.request({"clock_hz": 1, "samples": samples})
        self.assertEqual(status, 400)
        self.assertEqual(set(body), {"error"})

    def test_unknown_route_unchanged(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/performance/cycles",
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


if __name__ == "__main__":
    unittest.main()
