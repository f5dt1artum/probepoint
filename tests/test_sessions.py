import json
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from probepoint.breakpoints import BreakpointStore
from probepoint.server import make_server
from probepoint.sessions import SessionStore

EXECUTE = {"kind": "execute", "address": 0x1000, "enabled": True}
WATCH = {"kind": "write", "address": 0x2000, "size": 4, "enabled": False}


class SessionHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self) -> None:
        # Records are process-local by design; give each test empty stores.
        self.httpd.RequestHandlerClass.service.breakpoints = BreakpointStore()
        self.httpd.RequestHandlerClass.service.sessions = SessionStore()

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

    def create_session(self, body: object = ...) -> tuple[int, object]:
        if body is ...:
            body = {"name": "target"}
        return self.request("POST", "/v1/sessions", body)

    def make_session(self, name: str = "target") -> int:
        status, body = self.create_session({"name": name})
        self.assertEqual(status, 201)
        return body["id"]

    def bp(self, method: str, session_id: object, tail: str = "", body: object = ...):
        path = f"/v1/sessions/{session_id}/breakpoints{tail}"
        if body is ...:
            return self.request(method, path)
        return self.request(method, path, body)


class CreateSessionTest(SessionHttpTest):
    def test_create_returns_id_and_name_only(self) -> None:
        status, body = self.create_session({"name": "alpha"})
        self.assertEqual(status, 201)
        self.assertEqual(body, {"id": 1, "name": "alpha"})

    def test_ids_increment_and_are_not_reused(self) -> None:
        first = self.make_session("a")
        second = self.make_session("b")
        self.assertEqual((first, second), (1, 2))
        status, body = self.request("DELETE", "/v1/sessions/1")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": 1})
        third = self.make_session("c")
        self.assertEqual(third, 3)

    def test_name_is_trimmed(self) -> None:
        status, body = self.create_session({"name": "  padded\t"})
        self.assertEqual(status, 201)
        self.assertEqual(body["name"], "padded")
        # Unicode whitespace is trimmed too.
        status, body = self.create_session({"name": " wide "})
        self.assertEqual(status, 201)
        self.assertEqual(body["name"], "wide")

    def test_name_length_bounds(self) -> None:
        status, _ = self.create_session({"name": "x" * 64})
        self.assertEqual(status, 201)
        status, resp = self.create_session({"name": "y" * 65})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")
        # The limit applies after trimming.
        status, resp = self.create_session({"name": "  " + "z" * 65 + "  "})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_empty_after_trim_rejected(self) -> None:
        for name in ("", "   ", "\t\n "):
            with self.subTest(name=name):
                status, resp = self.create_session({"name": name})
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_invalid_request_not_json_object(self) -> None:
        status, resp = self.raw_request("POST", "/v1/sessions", b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for body in ([], "x", 42, None, 3.5, True):
            with self.subTest(body=body):
                status, resp = self.create_session(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_field_errors(self) -> None:
        cases = [
            {},
            {"name": "a", "extra": 1},
            {"name": 5},
            {"name": True},
            {"name": None},
            {"name": ["a"]},
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.create_session(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_duplicate_normalized_name_conflict(self) -> None:
        status, _ = self.create_session({"name": "  dup  "})
        self.assertEqual(status, 201)
        status, resp = self.create_session({"name": "dup"})
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "duplicate_session")

    def test_names_are_case_sensitive(self) -> None:
        status, _ = self.create_session({"name": "Target"})
        self.assertEqual(status, 201)
        status, _ = self.create_session({"name": "target"})
        self.assertEqual(status, 201)

    def test_name_reusable_after_delete(self) -> None:
        session_id = self.make_session("gone")
        status, _ = self.request("DELETE", f"/v1/sessions/{session_id}")
        self.assertEqual(status, 200)
        status, body = self.create_session({"name": "gone"})
        self.assertEqual(status, 201)
        self.assertEqual(body["name"], "gone")


class ListDeleteSessionTest(SessionHttpTest):
    def test_list_sorted_by_id(self) -> None:
        for name in ("c", "a", "b"):
            self.make_session(name)
        status, body = self.request("GET", "/v1/sessions")
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            [{"id": 1, "name": "c"}, {"id": 2, "name": "a"}, {"id": 3, "name": "b"}],
        )

    def test_list_empty(self) -> None:
        status, body = self.request("GET", "/v1/sessions")
        self.assertEqual(status, 200)
        self.assertEqual(body, [])

    def test_delete_returns_deleted(self) -> None:
        session_id = self.make_session()
        status, body = self.request("DELETE", f"/v1/sessions/{session_id}")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": session_id})
        status, resp = self.request("DELETE", f"/v1/sessions/{session_id}")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_missing_session_is_not_found(self) -> None:
        status, resp = self.request("DELETE", "/v1/sessions/9999")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_invalid_session_id_path(self) -> None:
        for raw in ("0", "-1", "abc", "1a", "1.5", "%201", "+1", "01"):
            with self.subTest(raw=raw):
                status, resp = self.request("DELETE", f"/v1/sessions/{raw}")
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_session_id")

    def test_unsupported_session_routes_not_found(self) -> None:
        for method, path, body in (
            ("GET", "/v1/sessions/1", ...),
            ("PATCH", "/v1/sessions/1", {"enabled": True}),
            ("POST", "/v1/sessions/1", {"name": "x"}),
            ("DELETE", "/v1/sessions", ...),
            ("GET", "/v1/sessions/", ...),
            ("GET", "/v1/sessions/1/", ...),
            ("GET", "/v1/sessions/1/breakpoints/", ...),
            ("GET", "/v1/sessions/1/breakpoints/1", ...),
        ):
            with self.subTest(method=method, path=path):
                if body is ...:
                    status, resp = self.request(method, path)
                else:
                    status, resp = self.request(method, path, body)
                self.assertEqual(status, 404)
                self.assertEqual(resp["error"]["code"], "not_found")


class SessionBreakpointTest(SessionHttpTest):
    def test_crud_mirrors_global_breakpoints(self) -> None:
        session_id = self.make_session()
        status, body = self.bp("POST", session_id, body=EXECUTE)
        self.assertEqual(status, 201)
        self.assertEqual(body, {"id": 1, "kind": "execute", "address": 0x1000, "enabled": True})

        status, body = self.bp("POST", session_id, body=WATCH)
        self.assertEqual(status, 201)
        self.assertEqual(body["id"], 2)

        status, body = self.bp("GET", session_id)
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body], [1, 2])

        status, body = self.bp("GET", session_id, "?kind=write&enabled=false")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body], [2])

        status, body = self.bp("PATCH", session_id, "/1", {"enabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(body["enabled"])

        status, body = self.bp("DELETE", session_id, "/1")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": 1})
        status, resp = self.bp("DELETE", session_id, "/1")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "breakpoint_not_found")

    def test_nested_field_and_query_errors(self) -> None:
        session_id = self.make_session()
        status, resp = self.bp("POST", session_id, body={"kind": "read", "address": 8, "enabled": True})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

        status, resp = self.bp("GET", session_id, "?kind=nope")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_query")

        status, resp = self.bp("PATCH", session_id, "/1", {"enabled": 0})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_nested_duplicate_scoped_to_session(self) -> None:
        first = self.make_session("one")
        second = self.make_session("two")
        status, _ = self.bp("POST", first, body=EXECUTE)
        self.assertEqual(status, 201)
        status, resp = self.bp("POST", first, body=EXECUTE)
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "duplicate_breakpoint")
        # The identical record is fine in another session...
        status, body = self.bp("POST", second, body=EXECUTE)
        self.assertEqual(status, 201)
        self.assertEqual(body["id"], 1)
        # ...and in the global collection.
        status, body = self.request("POST", "/v1/breakpoints", EXECUTE)
        self.assertEqual(status, 201)
        self.assertEqual(body["id"], 1)

    def test_global_breakpoints_unaffected_by_sessions(self) -> None:
        session_id = self.make_session()
        self.bp("POST", session_id, body=EXECUTE)
        status, body = self.request("GET", "/v1/breakpoints")
        self.assertEqual(status, 200)
        self.assertEqual(body, [])
        self.request("POST", "/v1/breakpoints", EXECUTE)
        status, body = self.bp("GET", session_id)
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 1)

    def test_nested_invalid_breakpoint_id(self) -> None:
        session_id = self.make_session()
        for raw in ("0", "-1", "abc", "01", "+1"):
            for method in ("PATCH", "DELETE"):
                with self.subTest(raw=raw, method=method):
                    status, resp = self.bp(method, session_id, f"/{raw}", {"enabled": True})
                    self.assertEqual(status, 400)
                    self.assertEqual(resp["error"]["code"], "invalid_breakpoint_id")

    def test_nested_invalid_session_id(self) -> None:
        for raw in ("0", "abc", "01"):
            with self.subTest(raw=raw):
                status, resp = self.bp("POST", raw, body=EXECUTE)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_session_id")
                status, resp = self.bp("GET", raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_session_id")

    def test_operations_on_deleted_session_return_404(self) -> None:
        session_id = self.make_session()
        self.bp("POST", session_id, body=EXECUTE)
        status, _ = self.request("DELETE", f"/v1/sessions/{session_id}")
        self.assertEqual(status, 200)
        for method, tail, body in (
            ("GET", "", ...),
            ("POST", "", EXECUTE),
            ("PATCH", "/1", {"enabled": True}),
            ("DELETE", "/1", ...),
        ):
            with self.subTest(method=method, tail=tail):
                status, resp = self.bp(method, session_id, tail, body)
                self.assertEqual(status, 404)
                self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_session_not_found_precedes_body_errors(self) -> None:
        session_id = self.make_session()
        self.request("DELETE", f"/v1/sessions/{session_id}")
        status, resp = self.bp("POST", session_id, body={"bogus": True})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_delete_discards_breakpoints_atomically(self) -> None:
        session_id = self.make_session()
        self.bp("POST", session_id, body=EXECUTE)
        self.bp("POST", session_id, body=WATCH)
        status, _ = self.request("DELETE", f"/v1/sessions/{session_id}")
        self.assertEqual(status, 200)
        # A fresh session starts from an empty store with ids from 1.
        new_id = self.make_session("other")
        status, body = self.bp("GET", new_id)
        self.assertEqual(status, 200)
        self.assertEqual(body, [])
        status, body = self.bp("POST", new_id, body=EXECUTE)
        self.assertEqual(status, 201)
        self.assertEqual(body["id"], 1)


class SessionConcurrencyTest(SessionHttpTest):
    def test_concurrent_same_name_create_only_one_wins(self) -> None:
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: self.create_session({"name": "race"}), range(32)))
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 31)
        for status, body in results:
            if status == 409:
                self.assertEqual(body["error"]["code"], "duplicate_session")

    def test_concurrent_create_ids_unique_and_contiguous(self) -> None:
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(
                pool.map(lambda i: self.create_session({"name": f"s{i}"}), range(64))
            )
        statuses = [status for status, _ in results]
        self.assertEqual(set(statuses), {201})
        ids = sorted(body["id"] for _, body in results)
        self.assertEqual(ids, list(range(1, 65)))

    def test_concurrent_delete_and_nested_ops(self) -> None:
        session_id = self.make_session()
        self.bp("POST", session_id, body=EXECUTE)

        outcomes = []

        def hammer(index: int) -> None:
            if index == 0:
                outcomes.append(self.request("DELETE", f"/v1/sessions/{session_id}"))
            else:
                outcomes.append(self.bp("POST", session_id, body=WATCH))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(hammer, range(16)))

        # The delete itself succeeded exactly once.
        deletes = [outcome for outcome in outcomes if outcome[1] == {"deleted": session_id}]
        self.assertEqual(len(deletes), 1)
        # Every nested op either fully preceded the delete (201, or 409 when
        # a sibling create won the duplicate check) or saw session_not_found.
        for status, body in outcomes:
            if body == {"deleted": session_id}:
                continue
            if status in (201, 409):
                continue
            self.assertEqual(status, 404)
            self.assertEqual(body["error"]["code"], "session_not_found")
        # Deleted data never resurfaces.
        status, resp = self.bp("GET", session_id)
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")


if __name__ == "__main__":
    unittest.main()
