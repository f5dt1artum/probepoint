import json
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from probepoint.breakpoints import BreakpointStore
from probepoint.server import make_server

EXECUTE = {"kind": "execute", "address": 0x1000, "enabled": True}


class BreakpointHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self) -> None:
        # Records are process-local by design; give each test an empty store.
        self.httpd.RequestHandlerClass.service.breakpoints = BreakpointStore()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, method: str, path: str, body: object = ...) -> tuple[int, object]:
        data = None
        headers = {}
        if body is not ...:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers=headers,
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

    def raw_request(self, method: str, path: str, raw: bytes) -> tuple[int, object]:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=raw,
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

    def create(self, body: object) -> tuple[int, object]:
        return self.request("POST", "/v1/breakpoints", body)

    def list(self, query: str = "") -> tuple[int, object]:
        return self.request("GET", f"/v1/breakpoints{query}")

    def patch(self, record_id: object, body: object) -> tuple[int, object]:
        return self.request("PATCH", f"/v1/breakpoints/{record_id}", body)

    def delete(self, record_id: object) -> tuple[int, object]:
        return self.request("DELETE", f"/v1/breakpoints/{record_id}")


class CreateTest(BreakpointHttpTest):
    def test_create_execute_normalized(self) -> None:
        status, body = self.create(EXECUTE)
        self.assertEqual(status, 201)
        self.assertEqual(
            body, {"id": 1, "kind": "execute", "address": 0x1000, "enabled": True}
        )
        self.assertNotIn("size", body)

    def test_create_watchpoint_normalized(self) -> None:
        status, body = self.create({"kind": "write", "address": 0x2000, "size": 4, "enabled": False})
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {"id": 1, "kind": "write", "address": 0x2000, "size": 4, "enabled": False},
        )

    def test_address_bounds(self) -> None:
        status, _ = self.create({"kind": "execute", "address": 0xFFFFFFFF, "enabled": True})
        self.assertEqual(status, 201)

    def test_invalid_request_not_json_object(self) -> None:
        status, resp = self.raw_request("POST", "/v1/breakpoints", b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for body in ([], "x", 42, None, 3.5):
            with self.subTest(body=body):
                status, resp = self.create(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        cases = [
            {},
            {"kind": "execute", "address": 0, "enabled": True, "extra": 1},
            {"kind": "bogus", "address": 0, "enabled": True},
            {"kind": 5, "address": 0, "enabled": True},
            {"kind": "execute", "address": -1, "enabled": True},
            {"kind": "execute", "address": 1 << 32, "enabled": True},
            {"kind": "execute", "address": 1.5, "enabled": True},
            {"kind": "execute", "address": "8", "enabled": True},
            {"kind": "execute", "address": 0, "enabled": 1},
            {"kind": "execute", "address": 0, "enabled": "yes"},
            {"kind": "execute", "address": 0, "enabled": True, "size": 3},
            {"kind": "execute", "address": 0, "enabled": True, "size": 0},
            {"kind": "execute", "address": 0, "enabled": True, "size": "4"},
            {"kind": "read", "address": 8, "enabled": True},
            {"kind": "write", "address": 7, "size": 4, "enabled": True},
            {"kind": "access", "address": 3, "size": 2, "enabled": True},
            {"kind": "read", "address": 8, "size": 2, "enabled": True, "x": 0},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.create(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_aligned_watchpoints_accepted(self) -> None:
        for kind, size in (("read", 1), ("write", 2), ("access", 8)):
            with self.subTest(kind=kind, size=size):
                status, body = self.create(
                    {"kind": kind, "address": 0x3000 + size, "size": size, "enabled": True}
                )
                self.assertEqual(status, 201, body)

    def test_duplicate_regardless_of_enabled(self) -> None:
        status, first = self.create({"kind": "read", "address": 0x4000, "size": 4, "enabled": True})
        self.assertEqual(status, 201)
        status, resp = self.create({"kind": "read", "address": 0x4000, "size": 4, "enabled": False})
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "duplicate_breakpoint")

    def test_same_address_different_kind_or_size_ok(self) -> None:
        base = {"kind": "write", "address": 0x5000, "size": 4, "enabled": True}
        status, _ = self.create(base)
        self.assertEqual(status, 201)
        status, _ = self.create({**base, "kind": "access"})
        self.assertEqual(status, 201)
        status, _ = self.create({**base, "size": 8, "address": 0x5000})
        self.assertEqual(status, 201)

    def test_field_validation_before_duplicate(self) -> None:
        status, _ = self.create({"kind": "write", "address": 0x6000, "size": 4, "enabled": True})
        self.assertEqual(status, 201)
        # Duplicate triad, but malformed payload -> invalid_field, not 409.
        status, resp = self.create({"kind": "write", "address": 0x6000, "enabled": True})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")


class ListTest(BreakpointHttpTest):
    def seed(self) -> None:
        seeds = [
            {"kind": "execute", "address": 0x100, "enabled": True},
            {"kind": "read", "address": 0x200, "size": 4, "enabled": False},
            {"kind": "write", "address": 0x208, "size": 8, "enabled": True},
        ]
        for body in seeds:
            status, _ = self.create(body)
            self.assertEqual(status, 201)

    def test_list_sorted_by_id(self) -> None:
        self.seed()
        status, body = self.list()
        self.assertEqual(status, 200)
        self.assertIsInstance(body, list)
        self.assertEqual([item["id"] for item in body], [1, 2, 3])

    def test_filter_by_kind(self) -> None:
        self.seed()
        status, body = self.list("?kind=read")
        self.assertEqual(status, 200)
        self.assertEqual([item["kind"] for item in body], ["read"])

    def test_filter_by_enabled(self) -> None:
        self.seed()
        status, body = self.list("?enabled=false")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body], [2])

    def test_filter_kind_and_enabled(self) -> None:
        self.seed()
        status, body = self.list("?kind=write&enabled=true")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body], [3])
        status, body = self.list("?kind=read&enabled=true")
        self.assertEqual(status, 200)
        self.assertEqual(body, [])

    def test_invalid_query(self) -> None:
        for query in (
            "?bogus=1",
            "?kind=read&kind=write",
            "?enabled=true&enabled=false",
            "?kind=nope",
            "?enabled=1",
            "?kind=",
            "?enabled=",
            "?kind=read&extra=2",
        ):
            with self.subTest(query=query):
                status, resp = self.list(query)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_query")


class UpdateDeleteTest(BreakpointHttpTest):
    def make_one(self) -> int:
        status, body = self.create({"kind": "write", "address": 0x7000, "size": 4, "enabled": True})
        self.assertEqual(status, 201)
        return body["id"]

    def test_patch_toggles_enabled(self) -> None:
        record_id = self.make_one()
        status, body = self.patch(record_id, {"enabled": False})
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], record_id)
        self.assertFalse(body["enabled"])
        self.assertEqual(body["kind"], "write")
        self.assertEqual(body["size"], 4)

    def test_patch_field_errors(self) -> None:
        record_id = self.make_one()
        for body in ({}, {"enabled": False, "x": 1}, {"enabled": 0}, {"id": 2}):
            with self.subTest(body=body):
                status, resp = self.patch(record_id, body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_delete_returns_deleted(self) -> None:
        record_id = self.make_one()
        status, body = self.delete(record_id)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": record_id})
        status, resp = self.delete(record_id)
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "breakpoint_not_found")

    def test_missing_positive_id_is_not_found(self) -> None:
        status, resp = self.patch(9999, {"enabled": True})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "breakpoint_not_found")
        status, resp = self.delete(9999)
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "breakpoint_not_found")

    def test_invalid_id_path(self) -> None:
        for raw in ("0", "-1", "abc", "1a", "1.5", "%201", "+1", "01"):
            for method in ("PATCH", "DELETE"):
                with self.subTest(raw=raw, method=method):
                    status, resp = self.request(method, f"/v1/breakpoints/{raw}", {"enabled": True})
                    self.assertEqual(status, 400)
                    self.assertEqual(resp["error"]["code"], "invalid_breakpoint_id")

    def test_update_and_delete_isolated(self) -> None:
        first = self.make_one()
        status, second_body = self.create(
            {"kind": "read", "address": 0x7100, "size": 1, "enabled": True}
        )
        self.assertEqual(status, 201)
        second = second_body["id"]
        self.patch(first, {"enabled": False})
        self.delete(second)
        status, body = self.list()
        self.assertEqual(status, 200)
        records = {item["id"]: item for item in body}
        self.assertFalse(records[first]["enabled"])
        self.assertNotIn(second, records)


class ConcurrencyTest(BreakpointHttpTest):
    def test_concurrent_create_ids_unique_and_contiguous(self) -> None:
        def create_one(index: int) -> tuple[int, object]:
            return self.create(
                {"kind": "write", "address": 0x8000 + index * 8, "size": 8, "enabled": True}
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(create_one, range(64)))
        statuses = [status for status, _ in results]
        self.assertEqual(set(statuses), {201})
        ids = sorted(body["id"] for _, body in results)
        self.assertEqual(len(set(ids)), 64)
        self.assertEqual(ids, list(range(ids[0], ids[0] + 64)))

        status, body = self.list()
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 64)


class RouteCompatibilityTest(BreakpointHttpTest):
    def test_healthz_unchanged(self) -> None:
        status, body = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_unknown_routes_still_not_found(self) -> None:
        status, resp = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")
        status, resp = self.request("DELETE", "/v1/breakpoints")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")

    def test_collection_get_rejects_post_query_style_paths(self) -> None:
        # Trailing slash is not the item resource nor the collection.
        status, resp = self.request("GET", "/v1/breakpoints/")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
