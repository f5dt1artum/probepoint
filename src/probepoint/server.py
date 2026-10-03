"""HTTP entry point for ProbePoint."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .backtrace import BacktraceError
from .breakpoints import BreakpointError, parse_breakpoint_id
from .frames import FrameError
from .rsp import RspError
from .service import Service
from .symbols import SymbolError

BREAKPOINTS_PATH = "/v1/breakpoints"
BREAKPOINTS_PREFIX = BREAKPOINTS_PATH + "/"

_BAD_REQUEST = object()  # sentinel: invalid_request response already sent


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

    def read_json_body(self) -> object:
        """Return the parsed JSON body.

        Returns ``_BAD_REQUEST`` after sending ``invalid_request`` when the
        body is not parseable JSON; a body that parses to ``null`` is still
        returned as ``None`` so the handler can apply its object check.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error_json(400, "invalid_request", "request body is not valid JSON")
            return _BAD_REQUEST

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

        routes = {
            "/v1/frames/encode": self.service.encode_frame,
            "/v1/frames/decode": self.service.decode_frame,
            "/v1/frames/decode-stream": self.service.decode_stream,
            "/v1/rsp/encode": self.service.encode_rsp_packet,
            "/v1/rsp/decode-stream": self.service.decode_rsp_stream,
            "/v1/rsp/commands/encode": self.service.encode_rsp_command,
            "/v1/rsp/commands/decode-response": self.service.decode_rsp_command_response,
            "/v1/backtrace": self.service.backtrace,
            "/v1/symbols/resolve": self.service.resolve_symbols,
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
        except SymbolError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        except (FrameError, RspError, BacktraceError) as exc:
            self.send_error_json(400, exc.code, exc.message)
            return
        self.send_json(200, result)

    def do_PATCH(self) -> None:
        parts = urlsplit(self.path)
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
        body = self.read_json_body()
        if body is _BAD_REQUEST:
            return
        try:
            result = self.service.update_breakpoint(record_id, body)
        except BreakpointError as exc:
            self.send_error_json(exc.status, exc.code, exc.message)
            return
        self.send_json(200, result)

    def do_DELETE(self) -> None:
        parts = urlsplit(self.path)
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
