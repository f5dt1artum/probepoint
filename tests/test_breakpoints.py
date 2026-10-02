import json
import threading
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server


class BreakpointHttpTest(unittest.TestCase):
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

    def request(self, method: str, path: str, body: object = ...) -> tuple[int, object]:
        data = None if body is ... else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def post_raw(self, path: str, raw: bytes) -> tuple[int, dict]:
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

    def create(self, **fields: object) -> tuple[int, object]:
        return self.request("POST", "/v1/breakpoints", fields)


class CreateTest(BreakpointHttpTest):
    def test_create_execute_normalized(self) -> None:
        status, body = self.create(kind="execute", address=0x1000, enabled=True)
        self.assertEqual(status, 201)
        assert isinstance(body, dict)
        self.assertEqual(body["kind"], "execute")
        self.assertEqual(body["address"], 0x1000)
        self.assertIsNone(body["size"])
        self.assertIs(body["enabled"], True)
        self.assertIsInstance(body["id"], int)
        self.assertGreater(body["id"], 0)

    def test_create_watchpoint_sizes(self) -> None:
        for index, size in enumerate((1, 2, 4, 8)):
            status, body = self.create(kind="write", address=0x2000 + index * 0x100, enabled=False, size=size)
            self.assertEqual(status, 201)
            assert isinstance(body, dict)
            self.assertEqual(body["size"], size)
            self.assertIs(body["enabled"], False)

    def test_create_boundary_address(self) -> None:
        status, body = self.create(kind="execute", address=0xFFFFFFFF, enabled=True)
        self.assertEqual(status, 201)
        assert isinstance(body, dict)
        self.assertEqual(body["address"], 0xFFFFFFFF)
        status, _ = self.create(kind="read", address=0xFFFFFFFF, enabled=True, size=1)
        self.assertEqual(status, 201)

    def test_invalid_request_body(self) -> None:
        status, body = self.post_raw("/v1/breakpoints", b"not json")
        self.assertEqual(status, 400)
        assert isinstance(body, dict)
        self.assertEqual(body["error"]["code"], "invalid_request")
        for payload in ([1], "x", 42, None):
            status, body = self.request("POST", "/v1/breakpoints", payload)
            self.assertEqual(status, 400)
            assert isinstance(body, dict)
            self.assertEqual(body["error"]["code"], "invalid_request")

    def test_invalid_fields(self) -> None:
        good = {"kind": "write", "address": 0x1000, "enabled": True, "size": 4}
        cases = [
            {},
            {"kind": "write", "address": 0x1000, "enabled": True},  # watchpoint missing size
            {"kind": "execute", "address": 0x1000, "enabled": True, "size": 4},
            {**good, "extra": 1},
            {**good, "kind": "jump"},
            {**good, "kind": 1},
            {**good, "address": -1},
            {**good, "address": 1 << 32},
            {**good, "address": 1.5},
            {**good, "address": True},
            {**good, "address": "4096"},
            {**good, "enabled": "yes"},
            {**good, "enabled": 1},
            {**good, "size": 3},
            {**good, "size": 0},
            {**good, "size": True},
            {"kind": "write", "address": 0x1001, "enabled": True, "size": 2},  # misaligned
            {"kind": "access", "address": 0x1004, "enabled": True, "size": 8},  # misaligned
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, body = self.request("POST", "/v1/breakpoints", payload)
                self.assertEqual(status, 400)
                assert isinstance(body, dict)
                self.assertEqual(body["error"]["code"], "invalid_field")

    def test_field_validation_precedes_duplicate_check(self) -> None:
        status, _ = self.create(kind="execute", address=0x4000, enabled=True)
        self.assertEqual(status, 201)
        # Same key but also malformed: invalid_field must win over 409.
        bad = {"kind": "execute", "address": 0x4000, "enabled": True, "size": 1}
        status, body = self.request("POST", "/v1/breakpoints", bad)
        self.assertEqual(status, 400)
        assert isinstance(body, dict)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_duplicate_regardless_of_enabled(self) -> None:
        status, first = self.create(kind="write", address=0x5000, enabled=True, size=4)
        self.assertEqual(status, 201)
        status, body = self.request(
            "POST", "/v1/breakpoints", {"kind": "write", "address": 0x5000, "enabled": False, "size": 4}
        )
        self.assertEqual(status, 409)
        assert isinstance(body, dict)
        self.assertEqual(body["error"]["code"], "duplicate_breakpoint")
        assert isinstance(first, dict)
        self.assertIs(first["enabled"], True)

    def test_same_address_different_kind_or_size_is_not_duplicate(self) -> None:
        base = 0x6000
        for payload in (
            {"kind": "execute", "address": base, "enabled": True},
            {"kind": "read", "address": base, "enabled": True, "size": 4},
            {"kind": "write", "address": base, "enabled": True, "size": 4},
            {"kind": "write", "address": base, "enabled": True, "size": 1},
        ):
            status, _ = self.request("POST", "/v1/breakpoints", payload)
            self.assertEqual(status, 201, payload)


class ListTest(BreakpointHttpTest):
    def seed(self, *records: dict) -> list[int]:
        ids = []
        for record in records:
            status, body = self.request("POST", "/v1/breakpoints", record)
            self.assertEqual(status, 201, record)
            assert isinstance(body, dict)
            ids.append(body["id"])
        return ids

    def test_list_sorted_and_filtered(self) -> None:
        base = 0x7000
        ids = self.seed(
            {"kind": "execute", "address": base, "enabled": True},
            {"kind": "read", "address": base + 0x10, "enabled": False, "size": 2},
            {"kind": "write", "address": base + 0x20, "enabled": True, "size": 4},
            {"kind": "read", "address": base + 0x30, "enabled": True, "size": 8},
        )
        status, body = self.request("GET", "/v1/breakpoints")
        self.assertEqual(status, 200)
        assert isinstance(body, list)
        seeded = [r for r in body if r["id"] in ids]
        self.assertEqual([r["id"] for r in seeded], ids)

        status, body = self.request("GET", "/v1/breakpoints?kind=read")
        self.assertEqual(status, 200)
        assert isinstance(body, list)
        self.assertEqual({r["id"] for r in body} & set(ids), {ids[1], ids[3]})
        self.assertTrue(all(r["kind"] == "read" for r in body))

        status, body = self.request("GET", "/v1/breakpoints?enabled=true")
        self.assertEqual(status, 200)
        assert isinstance(body, list)
        visible = {r["id"]: r for r in body}
        self.assertIn(ids[0], visible)
        self.assertNotIn(ids[1], visible)
        self.assertTrue(all(r["enabled"] for r in body))

        status, body = self.request("GET", "/v1/breakpoints?kind=read&enabled=false")
        self.assertEqual(status, 200)
        assert isinstance(body, list)
        self.assertEqual([r["id"] for r in body if r["id"] in ids], [ids[1]])

    def test_invalid_query(self) -> None:
        for query in (
            "?unknown=1",
            "?kind=read&kind=write",
            "?kind=nope",
            "?enabled=1",
            "?enabled=",
            "?kind=read&bogus=x",
        ):
            with self.subTest(query=query):
                status, body = self.request("GET", f"/v1/breakpoints{query}")
                self.assertEqual(status, 400)
                assert isinstance(body, dict)
                self.assertEqual(body["error"]["code"], "invalid_query")


class ItemTest(BreakpointHttpTest):
    def make_one(self, address: int = 0x8000) -> int:
        status, body = self.create(kind="write", address=address, enabled=True, size=4)
        self.assertEqual(status, 201)
        assert isinstance(body, dict)
        return int(body["id"])

    def test_patch_toggles_enabled(self) -> None:
        record_id = self.make_one()
        status, body = self.request("PATCH", f"/v1/breakpoints/{record_id}", {"enabled": False})
        self.assertEqual(status, 200)
        assert isinstance(body, dict)
        self.assertIs(body["enabled"], False)
        self.assertEqual(body["id"], record_id)
        self.assertEqual(body["kind"], "write")
        status, body = self.request("GET", "/v1/breakpoints")
        assert isinstance(body, list)
        self.assertIs(next(r for r in body if r["id"] == record_id)["enabled"], False)

    def test_patch_validation(self) -> None:
        record_id = self.make_one(0x8100)
        for payload in ({"enabled": "no"}, {"enabled": True, "kind": "read"}, {}):
            with self.subTest(payload=payload):
                status, body = self.request("PATCH", f"/v1/breakpoints/{record_id}", payload)
                self.assertEqual(status, 400)
                assert isinstance(body, dict)
                self.assertEqual(body["error"]["code"], "invalid_field")
        status, body = self.request("PATCH", f"/v1/breakpoints/{record_id}", [True])
        self.assertEqual(status, 400)
        assert isinstance(body, dict)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_delete(self) -> None:
        record_id = self.make_one(0x8200)
        status, body = self.request("DELETE", f"/v1/breakpoints/{record_id}")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": record_id})
        status, body = self.request("DELETE", f"/v1/breakpoints/{record_id}")
        self.assertEqual(status, 404)
        assert isinstance(body, dict)
        self.assertEqual(body["error"]["code"], "breakpoint_not_found")
        # Deleted id is not reused.
        status, body = self.create(kind="execute", address=0x8210, enabled=True)
        self.assertEqual(status, 201)
        assert isinstance(body, dict)
        self.assertNotEqual(body["id"], record_id)
        self.assertGreater(body["id"], record_id)

    def test_unknown_positive_id_is_404(self) -> None:
        for method, payload in (("PATCH", {"enabled": True}), ("DELETE", ...)):
            status, body = self.request(method, "/v1/breakpoints/99999999", payload)
            self.assertEqual(status, 404)
            assert isinstance(body, dict)
            self.assertEqual(body["error"]["code"], "breakpoint_not_found")

    def test_invalid_path_id(self) -> None:
        for raw in ("0", "-1", "abc", "1x", "1.5"):
            for method, payload in (("PATCH", {"enabled": True}), ("DELETE", ...)):
                with self.subTest(method=method, raw=raw):
                    status, body = self.request(method, f"/v1/breakpoints/{raw}", payload)
                    self.assertEqual(status, 400)
                    assert isinstance(body, dict)
                    self.assertEqual(body["error"]["code"], "invalid_breakpoint_id")

    def test_update_and_delete_isolate_other_records(self) -> None:
        first = self.make_one(0x8300)
        second = self.make_one(0x8400)
        status, updated = self.request("PATCH", f"/v1/breakpoints/{first}", {"enabled": False})
        self.assertEqual(status, 200)
        status, body = self.request("GET", "/v1/breakpoints")
        assert isinstance(body, list)
        records = {r["id"]: r for r in body}
        self.assertIs(records[first]["enabled"], False)
        self.assertIs(records[second]["enabled"], True)
        assert isinstance(updated, dict)
        self.assertEqual(updated["id"], first)
        self.request("DELETE", f"/v1/breakpoints/{first}")
        status, body = self.request("GET", "/v1/breakpoints")
        assert isinstance(body, list)
        self.assertIn(second, {r["id"] for r in body})


class ConcurrencyTest(BreakpointHttpTest):
    def test_concurrent_creates_get_distinct_consecutive_ids(self) -> None:
        count = 32
        results: list[tuple[int, object]] = [None] * count  # type: ignore[list-item]

        def worker(index: int) -> None:
            results[index] = self.request(
                "POST",
                "/v1/breakpoints",
                {"kind": "access", "address": 0x9000 + index * 8, "enabled": True, "size": 8},
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        ids = []
        for status, body in results:
            self.assertEqual(status, 201)
            assert isinstance(body, dict)
            ids.append(body["id"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sorted(ids), list(range(min(ids), max(ids) + 1)))

        status, body = self.request("GET", "/v1/breakpoints")
        self.assertEqual(status, 200)
        assert isinstance(body, list)
        for record in body:
            self.assertEqual(set(record), {"id", "kind", "address", "size", "enabled"})


class RouteCompatibilityTest(BreakpointHttpTest):
    def test_healthz_unchanged(self) -> None:
        status, body = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        assert isinstance(body, dict)
        self.assertEqual(body["status"], "ok")

    def test_unknown_paths_still_404(self) -> None:
        for method, path, payload in (
            ("GET", "/nope", ...),
            ("POST", "/nope", {}),
            ("PATCH", "/v1/breakpoints", {"enabled": True}),
            ("DELETE", "/v1/breakpoints", ...),
            ("GET", "/v1/frames/encode", ...),
        ):
            with self.subTest(method=method, path=path):
                status, body = self.request(method, path, payload)
                self.assertEqual(status, 404)
                assert isinstance(body, dict)
                self.assertEqual(body["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
