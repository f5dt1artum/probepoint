"""HTTP entry point for ProbePoint."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .backtrace import BacktraceError
from .breakpoints import BreakpointError, parse_breakpoint_id
from .cycles import CyclesError
from .frames import FrameError
from .itm import ItmError
from .rsp import RspError
from .service import Service
from .sessions import SessionError, parse_session_id
from .symbols import SymbolResolveError

BREAKPOINTS_PATH = "/v1/breakpoints"
BREAKPOINTS_PREFIX = BREAKPOINTS_PATH + "/"
SESSIONS_PATH = "/v1/sessions"
SESSIONS_PREFIX = SESSIONS_PATH + "/"
SESSION_BREAKPOINTS = "breakpoints"

_BAD_REQUEST = object()  # sentinel: invalid_request response already sent


def session_route(path: str) -> tuple[str, str | None] | None:
    """Split a ``/v1/sessions/...`` path into (raw session id, subpath).

    ``subpath`` is ``None`` for the session item itself, ``"breakpoints"``
    for the nested collection and ``"breakpoints/<rest>"`` for anything
    below it. Returns ``None`` when there is no usable id segment.
    """
    tail = path[len(SESSIONS_PREFIX) :]
    raw_id, sep, rest = tail.partition("/")
    if not raw_id:
        return None
    return raw_id, (rest if sep else None)


def env_address() -> tuple[str, int]:
    raw = os.environ.get("PROBEPOINT_ADDR", "127.0.0.1:8080")
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"invalid PROBEPOINT_ADDR: {raw!r}")
    return host, int(port)


class Handler(BaseHTTPRequestHandler):
    service = Service()

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, code: str, message: str) -> None:
        self.send_json(status, {"error": {"code": code, "message": message}})

    def read_raw_body(self) -> bytes:
        """Consume the request body so responses never reset the connection."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def parse_json_body(self, raw: bytes) -> object:
        """Parse an already-read body, sending ``invalid_request`` on failure."""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error_json(400, "invalid_request", "request body is not valid JSON")
            return _BAD_REQUEST

    def read_json_body(self) -> object:
        """Return the parsed JSON body.

        Returns ``_BAD_REQUEST`` after sending ``invalid_request`` when the
        body is not parseable JSON; a body that parses to ``null`` is still
        returned as ``None`` so the handler can apply its object check.
        """
        return self.parse_json_body(self.read_raw_body())

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        if parts.path == BREAKPOINTS_PATH:
            try:
                result = self.service.list_breakpoints(parts.query)
            except BreakpointError as exc:
                self.send_error_json(exc.status, exc.code, exc.message)
                return
            self.send_json(200, result)
            return
        if parts.path == SESSIONS_PATH:
            self.send_json(200, self.service.list_sessions())
            return
        if parts.path.startswith(SESSIONS_PREFIX):
            route = session_route(parts.path)
            if route is not None and route[1] == SESSION_BREAKPOINTS:
                try:
                    session_id = parse_session_id(route[0])
                    self.service.require_session(session_id)
                    result = self.service.list_session_breakpoints(session_id, parts.query)
                except (SessionError, BreakpointError) as exc:
                    self.send_error_json(exc.status, exc.code, exc.message)
                    return
                self.send_json(200, result)
                return
        self.send_error_json(404, "not_found", f"no route for {self.path}")

    def do_POST(self) -> None:
        if self.path == BREAKPOINTS_PATH:
            body = self.read_json_body()
            if body is _BAD_REQUEST:
                return
            try:
                result = self.service.create_breakpoint(body)
            except BreakpointError as exc:
                self.send_error_json(exc.status, exc.code, exc.message)
                return
            self.send_json(201, result)
            return

        if self.path == SESSIONS_PATH:
            body = self.read_json_body()
            if body is _BAD_REQUEST:
                return
            try:
                result = self.service.create_session(body)
            except SessionError as exc:
                self.send_error_json(exc.status, exc.code, exc.message)
                return
            self.send_json(201, result)
            return

        parts = urlsplit(self.path)
        if parts.path.startswith(SESSIONS_PREFIX):
            route = session_route(parts.path)
            if route is not None and route[1] == SESSION_BREAKPOINTS:
                # Consume the body before validating so a racing session
                # delete still gets a clean 404 response on the wire.
                raw = self.read_raw_body()
                try:
                    session_id = parse_session_id(route[0])
                    self.service.require_session(session_id)
                except SessionError as exc:
                    self.send_error_json(exc.status, exc.code, exc.message)
                    return
                body = self.parse_json_body(raw)
                if body is _BAD_REQUEST:
                    return
                try:
                    result = self.service.create_session_breakpoint(session_id, body)
                except (SessionError, BreakpointError) as exc:
                    self.send_error_json(exc.status, exc.code, exc.message)
                    return
                self.send_json(201, result)
                return

        routes = {
            "/v1/frames/encode": self.service.encode_frame,
            "/v1/frames/decode": self.service.decode_frame,
            "/v1/frames/decode-stream": self.service.decode_stream,
            "/v1/trace/itm/decode-stream": self.service.decode_itm_stream,
            "/v1/rsp/encode": self.service.encode_rsp_packet,
            "/v1/rsp/decode-stream": self.service.decode_rsp_stream,
            "/v1/rsp/commands/encode": self.service.encode_rsp_command,
            "/v1/rsp/commands/decode-response": self.service.decode_rsp_command_response,
            "/v1/backtrace": self.service.backtrace,
            "/v1/symbols/resolve": self.service.resolve_symbols,
            "/v1/performance/cycles/analyze": self.service.analyze_cycles,
        }
        handler = routes.get(self.path)
        if handler is None:
            self.send_error_json(404, "not_found", f"no route for {self.path}")
            return
        body = self.read_json_body()
        if body is _BAD_REQUEST:
            return
        try:
            result = handler(body)
        except SymbolResolveError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        except (FrameError, ItmError, RspError, BacktraceError, CyclesError) as exc:
            self.send_error_json(400, exc.code, exc.message)
            return
        self.send_json(200, result)

    def do_PATCH(self) -> None:
        parts = urlsplit(self.path)
        if parts.path.startswith(SESSIONS_PREFIX):
            route = session_route(parts.path)
            if route is not None and route[1] is not None:
                raw_id = self._nested_breakpoint_id(route[1])
                if raw_id is not None:
                    self._handle_session_breakpoint_patch(route[0], raw_id)
                    return
        if not parts.path.startswith(BREAKPOINTS_PREFIX):
            self.send_error_json(404, "not_found", f"no route for {self.path}")
            return
        raw_id = parts.path[len(BREAKPOINTS_PREFIX) :]
        if not raw_id:
            self.send_error_json(404, "not_found", f"no route for {self.path}")
            return
        # Consume the body before validating so error responses are never
        # cut short by unread request data resetting the connection.
        raw = self.read_raw_body()
        try:
            record_id = parse_breakpoint_id(raw_id)
        except BreakpointError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        body = self.parse_json_body(raw)
        if body is _BAD_REQUEST:
            return
        try:
            result = self.service.update_breakpoint(record_id, body)
        except BreakpointError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        self.send_json(200, result)

    def _nested_breakpoint_id(self, subpath: str) -> str | None:
        """Return the raw breakpoint id below ``breakpoints/``, else None."""
        prefix = SESSION_BREAKPOINTS + "/"
        if not subpath.startswith(prefix):
            return None
        raw_id = subpath[len(prefix) :]
        return raw_id or None

    def _handle_session_breakpoint_patch(self, raw_session_id: str, raw_id: str) -> None:
        # Consume the body before validating so a racing session delete
        # still gets a clean 404 response on the wire.
        raw = self.read_raw_body()
        try:
            session_id = parse_session_id(raw_session_id)
            self.service.require_session(session_id)
            record_id = parse_breakpoint_id(raw_id)
        except (SessionError, BreakpointError) as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        body = self.parse_json_body(raw)
        if body is _BAD_REQUEST:
            return
        try:
            result = self.service.update_session_breakpoint(session_id, record_id, body)
        except (SessionError, BreakpointError) as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        self.send_json(200, result)

    def do_DELETE(self) -> None:
        parts = urlsplit(self.path)
        if parts.path.startswith(SESSIONS_PREFIX):
            route = session_route(parts.path)
            if route is not None:
                if route[1] is None:
                    self._handle_session_delete(route[0])
                    return
                raw_id = self._nested_breakpoint_id(route[1])
                if raw_id is not None:
                    self._handle_session_breakpoint_delete(route[0], raw_id)
                    return
        if not parts.path.startswith(BREAKPOINTS_PREFIX):
            self.send_error_json(404, "not_found", f"no route for {self.path}")
            return
        raw_id = parts.path[len(BREAKPOINTS_PREFIX) :]
        if not raw_id:
            self.send_error_json(404, "not_found", f"no route for {self.path}")
            return
        try:
            record_id = parse_breakpoint_id(raw_id)
        except BreakpointError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        try:
            result = self.service.delete_breakpoint(record_id)
        except BreakpointError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        self.send_json(200, result)

    def _handle_session_delete(self, raw_session_id: str) -> None:
        try:
            session_id = parse_session_id(raw_session_id)
            result = self.service.delete_session(session_id)
        except SessionError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        self.send_json(200, result)

    def _handle_session_breakpoint_delete(self, raw_session_id: str, raw_id: str) -> None:
        try:
            session_id = parse_session_id(raw_session_id)
            self.service.require_session(session_id)
            record_id = parse_breakpoint_id(raw_id)
            result = self.service.delete_session_breakpoint(session_id, record_id)
        except (SessionError, BreakpointError) as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        self.send_json(200, result)

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence per-request logging so recorded output stays stable."""


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    # Bind a fresh Service per server so separate server instances never
    # share in-process breakpoint state.
    handler = type("BoundHandler", (Handler,), {"service": Service()})
    return ThreadingHTTPServer((host, port), handler)


def main() -> int:
    parser = argparse.ArgumentParser(prog="probepoint.server", description="嵌入式调试与探针工具链")
    host, port = env_address()
    parser.add_argument("--host", default=host)
    parser.add_argument("--port", type=int, default=port)
    args = parser.parse_args()
    httpd = make_server(args.host, args.port)
    print(f"ProbePoint listening on http://{args.host}:{httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
