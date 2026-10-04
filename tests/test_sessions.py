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
WATCH = {"kind": "write", "address": 0x2000, "size": 4, "enabled": True}


class SessionHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    def setUp(self) -> None:
        # All state is process-local; give each test empty stores.
        service = self.httpd.RequestHandlerClass.service
        service.breakpoints = BreakpointStore()
        service.sessions = SessionStore()

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

    def create_session(self, body: object = ..., name: str = "target-a"):
        if body is ...:
            body = {"name": name}
        return self.request("POST", "/v1/sessions", body)

    def list_sessions(self) -> tuple[int, object]:
        return self.request("GET", "/v1/sessions")

    def delete_session(self, session_id: object) -> tuple[int, object]:
        return self.request("DELETE", f"/v1/sessions/{session_id}")

    def make_session(self, name: str = "target-a") -> int:
        status, body = self.create_session(name=name)
        self.assertEqual(status, 201, body)
        return body["id"]

    def spath(self, session_id: object, suffix: str = "") -> str:
        return f"/v1/sessions/{session_id}/breakpoints{suffix}"

    def s_create(self, session_id: object, body: object) -> tuple[int, object]:
        return self.request("POST", self.spath(session_id), body)

    def s_list(self, session_id: object, query: str = "") -> tuple[int, object]:
        return self.request("GET", self.spath(session_id) + query)

    def s_patch(self, session_id: object, bp_id: object, body: object) -> tuple[int, object]:
        return self.request("PATCH", self.spath(session_id, f"/{bp_id}"), body)

    def s_delete(self, session_id: object, bp_id: object) -> tuple[int, object]:
        return self.request("DELETE", self.spath(session_id, f"/{bp_id}"))


class SessionCrudTest(SessionHttpTest):
    def test_create_returns_only_id_and_name(self) -> None:
        status, body = self.create_session(name="  target-a  ")
        self.assertEqual(status, 201)
        self.assertEqual(body, {"id": 1, "name": "target-a"})

    def test_trims_unicode_whitespace(self) -> None:
        status, body = self.create_session({"name": "　\ttarget-b\n "})
        self.assertEqual(status, 201)
        self.assertEqual(body["name"], "target-b")

    def test_ids_increment_from_one_and_not_reused(self) -> None:
        first = self.make_session("a")
        second = self.make_session("b")
        self.assertEqual((first, second), (1, 2))
        self.assertEqual(self.delete_session(first)[0], 200)
        third = self.make_session("c")
        self.assertEqual(third, 3)

    def test_list_sorted_ascending_live_only(self) -> None:
        status, body = self.list_sessions()
        self.assertEqual(status, 200)
        self.assertEqual(body, [])
        self.make_session("a")
        self.make_session("b")
        self.make_session("c")
        self.delete_session(2)
        status, body = self.list_sessions()
        self.assertEqual(status, 200)
        self.assertEqual(body, [{"id": 1, "name": "a"}, {"id": 3, "name": "c"}])

    def test_delete_returns_deleted_then_not_found(self) -> None:
        session_id = self.make_session()
        status, body = self.delete_session(session_id)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": session_id})
        status, resp = self.delete_session(session_id)
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_name_length_bounds(self) -> None:
        status, _ = self.create_session({"name": "a" * 64})
        self.assertEqual(status, 201)
        status, resp = self.create_session({"name": "a" * 65})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_empty_or_whitespace_name_rejected(self) -> None:
        for name in ("", "   ", "\t\n　 "):
            with self.subTest(name=name):
                status, resp = self.create_session({"name": name})
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_field_errors(self) -> None:
        for body in (
            {},
            {"name": "x", "extra": 1},
            {"name": 7},
            {"name": ["x"]},
            {"name": True},
            {"name": None},
        ):
            with self.subTest(body=body):
                status, resp = self.create_session(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_invalid_request_not_json_object(self) -> None:
        status, resp = self.raw_request("POST", "/v1/sessions", b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for body in ([], "x", 42, None, 3.5):
            with self.subTest(body=body):
                status, resp = self.create_session(body)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_empty_body_is_invalid_request(self) -> None:
        status, resp = self.request("POST", "/v1/sessions")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")

    def test_duplicate_name_conflict(self) -> None:
        self.assertEqual(self.create_session({"name": "dup"})[0], 201)
        status, resp = self.create_session({"name": "dup"})
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "duplicate_session")
        # Surrounding whitespace normalizes to the same live name.
        status, resp = self.create_session({"name": "  dup　"})
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"]["code"], "duplicate_session")

    def test_names_case_sensitive(self) -> None:
        self.assertEqual(self.create_session({"name": "Target"})[0], 201)
        status, _ = self.create_session({"name": "target"})
        self.assertEqual(status, 201)
        status, _ = self.create_session({"name": "TARGET"})
        self.assertEqual(status, 201)

    def test_name_reusable_after_delete(self) -> None:
        first = self.make_session("reuse")
        self.delete_session(first)
        status, body = self.create_session({"name": "reuse"})
        self.assertEqual(status, 201)
        self.assertGreater(body["id"], first)

    def test_invalid_session_id_paths(self) -> None:
        for raw in ("0", "-1", "01", "abc", "1a", "1.5", "+1", "%201"):
            with self.subTest(raw=raw):
                status, resp = self.request("GET", f"/v1/sessions/{raw}/breakpoints")
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_session_id")
                status, resp = self.delete_session(raw)
                self.assertEqual(status, 400)
                self.assertEqual(resp["error"]["code"], "invalid_session_id")

    def test_missing_session_is_not_found(self) -> None:
        for method, path in (
            ("GET", "/v1/sessions/9999/breakpoints"),
            ("POST", "/v1/sessions/9999/breakpoints"),
            ("PATCH", "/v1/sessions/9999/breakpoints/1"),
            ("DELETE", "/v1/sessions/9999/breakpoints/1"),
        ):
            with self.subTest(method=method):
                kwargs = {} if method == "GET" else {"body": EXECUTE if method == "POST" else {"enabled": False}}
                status, resp = self.request(method, path, **kwargs)
                self.assertEqual(status, 404)
                self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_unknown_session_routes(self) -> None:
        # No single-session GET/PATCH; no collection DELETE.
        status, resp = self.request("GET", "/v1/sessions/1")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")
        status, resp = self.request("PATCH", "/v1/sessions/1", {"name": "x"})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")
        status, resp = self.request("DELETE", "/v1/sessions")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")
        status, resp = self.request("POST", "/v1/sessions/1", {})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")
        status, resp = self.request("GET", "/v1/sessions/1/targets")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")
        for method in ("GET", "POST"):
            status, resp = self.request(method, "/v1/sessions/1/breakpoints/")
            self.assertEqual(status, 404)
            self.assertEqual(resp["error"]["code"], "not_found")
        status, resp = self.request("GET", "/v1/sessions/")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")


class SessionBreakpointsTest(SessionHttpTest):
    def test_ids_start_at_one_per_session(self) -> None:
        a = self.make_session("a")
        b = self.make_session("b")
        for session_id in (a, b):
            status, body = self.s_create(session_id, EXECUTE)
            self.assertEqual(status, 201)
            self.assertEqual(body["id"], 1)
            status, body = self.s_create(session_id, WATCH)
            self.assertEqual(status, 201)
            self.assertEqual(body["id"], 2)

    def test_same_record_allowed_in_different_sessions(self) -> None:
        a = self.make_session("a")
        b = self.make_session("b")
        self.assertEqual(self.s_create(a, WATCH)[0], 201)
        self.assertEqual(self.s_create(b, WATCH)[0], 201)
        self.assertEqual(self.s_create(a, WATCH)[1]["error"]["code"], "duplicate_breakpoint")
        self.assertEqual(self.s_create(b, WATCH)[1]["error"]["code"], "duplicate_breakpoint")

    def test_full_crud_and_filters(self) -> None:
        session_id = self.make_session()
        self.assertEqual(self.s_create(session_id, EXECUTE)[0], 201)
        status, body = self.s_create(
            session_id, {"kind": "read", "address": 0x200, "size": 4, "enabled": False}
        )
        self.assertEqual(status, 201)
        bp_id = body["id"]

        status, body = self.s_list(session_id)
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body], [1, 2])
        status, body = self.s_list(session_id, "?kind=read&enabled=false")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body], [2])

        status, body = self.s_patch(session_id, bp_id, {"enabled": True})
        self.assertEqual(status, 200)
        self.assertTrue(body["enabled"])

        status, body = self.s_delete(session_id, bp_id)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"deleted": bp_id})
        status, resp = self.s_delete(session_id, bp_id)
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "breakpoint_not_found")

    def test_error_semantics_match_global(self) -> None:
        session_id = self.make_session()
        status, resp = self.s_create(session_id, {"kind": "execute", "address": -1, "enabled": True})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")
        status, resp = self.raw_request(
            "POST", self.spath(session_id), b"{not json"
        )
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_request")
        for query in ("?bogus=1", "?kind=nope", "?enabled=1"):
            status, resp = self.s_list(session_id, query)
            self.assertEqual(status, 400)
            self.assertEqual(resp["error"]["code"], "invalid_query")
        status, resp = self.s_patch(session_id, 1, {"enabled": "yes"})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_field")

    def test_invalid_breakpoint_id_in_nested_path(self) -> None:
        session_id = self.make_session()
        for raw in ("0", "01", "-1", "abc"):
            for method in ("PATCH", "DELETE"):
                with self.subTest(raw=raw, method=method):
                    body = {"enabled": True} if method == "PATCH" else ...
                    status, resp = self.request(
                        method, self.spath(session_id, f"/{raw}"), body
                    )
                    self.assertEqual(status, 400)
                    self.assertEqual(resp["error"]["code"], "invalid_breakpoint_id")

    def test_session_id_validated_before_breakpoint_id(self) -> None:
        status, resp = self.request("PATCH", "/v1/sessions/0/breakpoints/0", {"enabled": True})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_session_id")
        # Valid-syntax but missing session still yields the path-level
        # breakpoint id error first.
        status, resp = self.request("PATCH", "/v1/sessions/9999/breakpoints/0", {"enabled": True})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_breakpoint_id")

    def test_delete_session_atomically_drops_breakpoints(self) -> None:
        session_id = self.make_session()
        self.s_create(session_id, EXECUTE)
        self.s_create(session_id, WATCH)
        self.assertEqual(self.delete_session(session_id)[0], 200)
        for method, path, body in (
            ("GET", self.spath(session_id), ...),
            ("POST", self.spath(session_id), EXECUTE),
            ("PATCH", self.spath(session_id, "/1"), {"enabled": False}),
            ("DELETE", self.spath(session_id, "/1"), ...),
        ):
            status, resp = self.request(method, path, body)
            self.assertEqual(status, 404)
            self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_deleted_session_precedence_over_body_and_bp_errors(self) -> None:
        session_id = self.make_session()
        self.delete_session(session_id)
        # Malformed JSON body on a deleted session still reports the session.
        status, resp = self.raw_request("POST", self.spath(session_id), b"not json")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")
        status, resp = self.raw_request(
            "PATCH", self.spath(session_id, "/1"), b"not json"
        )
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")
        # Deleted session outranks an invalid field body, but path-level
        # breakpoint id syntax is still parsed first.
        status, resp = self.s_create(session_id, {"bogus": True})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")
        status, resp = self.s_patch(session_id, 1, {"bogus": True})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "session_not_found")

    def test_session_breakpoints_independent_of_global(self) -> None:
        session_id = self.make_session()
        self.request("POST", "/v1/breakpoints", WATCH)
        self.s_create(session_id, WATCH)
        status, global_list = self.request("GET", "/v1/breakpoints")
        self.assertEqual(status, 200)
        self.assertEqual(len(global_list), 1)
        status, session_list = self.s_list(session_id)
        self.assertEqual(status, 200)
        self.assertEqual(len(session_list), 1)
        # Deleting inside the session leaves the global record untouched.
        self.s_delete(session_id, 1)
        status, global_list = self.request("GET", "/v1/breakpoints")
        self.assertEqual([item["id"] for item in global_list], [1])


class ConcurrencyTest(SessionHttpTest):
    def test_concurrent_same_name_single_winner(self) -> None:
        def create_one(_: int) -> tuple[int, object]:
            return self.create_session({"name": "only-one"})

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(create_one, range(32)))
        created = [body for status, body in results if status == 201]
        conflicts = [status for status, _ in results if status != 201]
        self.assertEqual(len(created), 1)
        self.assertEqual(set(conflicts), {409})
        self.assertTrue(all(b["error"]["code"] == "duplicate_session" for s, b in results if s != 201))
        self.assertEqual(self.list_sessions()[1], [{"id": 1, "name": "only-one"}])

    def test_concurrent_distinct_names(self) -> None:
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda i: self.create_session({"name": f"s{i}"}), range(64)))
        self.assertEqual({status for status, _ in results}, {201})
        ids = sorted(body["id"] for _, body in results)
        self.assertEqual(ids, list(range(1, 65)))

    def test_delete_races_operations(self) -> None:
        sessions = [self.make_session(f"race{i}") for i in range(8)]

        def ops(session_id: int) -> None:
            for _ in range(50):
                status, _ = self.s_create(session_id, EXECUTE)
                self.assertIn(status, (201, 404, 409))
                status, _ = self.s_list(session_id)
                self.assertIn(status, (200, 404))

        def deleter() -> None:
            for session_id in sessions:
                status, _ = self.delete_session(session_id)
                self.assertEqual(status, 200)
                # Once deleted, the session can never come back.
                for _ in range(10):
                    follow, _ = self.s_list(session_id)
                    self.assertEqual(follow, 404)
                _, follow = self.list_sessions()
                self.assertNotIn(session_id, [item["id"] for item in follow])

        workers = [threading.Thread(target=ops, args=(sid,)) for sid in sessions]
        workers.append(threading.Thread(target=deleter))
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        status, body = self.list_sessions()
        self.assertEqual(status, 200)
        self.assertEqual(body, [])


class SessionStoreAtomicityTest(unittest.TestCase):
    """Store-level guarantee: a delete is serialized with session actions."""

    def test_delete_waits_for_inflight_action(self) -> None:
        store = SessionStore()
        store.create("target")
        action_started = threading.Event()
        release_action = threading.Event()
        action_done = threading.Event()

        def run_action() -> None:
            with store.guard_session(1):
                action_started.set()
                self.assertTrue(release_action.wait(timeout=5))
            action_done.set()

        worker = threading.Thread(target=run_action)
        worker.start()
        self.assertTrue(action_started.wait(timeout=5))

        delete_returned = threading.Event()

        def run_delete() -> None:
            store.delete(1)
            delete_returned.set()

        deleter = threading.Thread(target=run_delete)
        deleter.start()
        # While the action runs, delete must wait rather than remove the session.
        self.assertFalse(delete_returned.wait(timeout=0.5))
        release_action.set()
        self.assertTrue(action_done.wait(timeout=5))
        self.assertTrue(delete_returned.wait(timeout=5))
        worker.join()
        deleter.join()
        from probepoint.sessions import SessionError

        with self.assertRaises(SessionError) as ctx:
            with store.guard_session(1):
                pass
        self.assertEqual(ctx.exception.code, "session_not_found")

    def test_action_after_delete_is_session_not_found(self) -> None:
        from probepoint.sessions import SessionError

        store = SessionStore()
        store.create("target")
        store.delete(1)
        with self.assertRaises(SessionError) as ctx:
            with store.guard_session(1):
                pass
        self.assertEqual(ctx.exception.code, "session_not_found")
        self.assertEqual(ctx.exception.status, 404)

    def test_different_sessions_stay_concurrent(self) -> None:
        store = SessionStore()
        store.create("a")
        store.create("b")
        first_holds = threading.Event()
        release = threading.Event()

        def hold_first() -> None:
            with store.guard_session(1):
                first_holds.set()
                release.wait(timeout=5)

        worker = threading.Thread(target=hold_first)
        worker.start()
        self.assertTrue(first_holds.wait(timeout=5))
        # Session 2's guard is independent and must not block.
        entered = threading.Event()

        def touch_second() -> None:
            with store.guard_session(2):
                entered.set()

        other = threading.Thread(target=touch_second)
        other.start()
        self.assertTrue(entered.wait(timeout=5))
        release.set()
        worker.join()
        other.join()


if __name__ == "__main__":
    unittest.main()
