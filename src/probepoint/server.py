"""HTTP entry point for ProbePoint."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .breakpoints import BreakpointError
from .frames import FrameError
from .service import Service

COLLECTION_PATH = "/v1/breakpoints"
ITEM_PREFIX = "/v1/breakpoints/"


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

    def send_error_body(self, exc: FrameError | BreakpointError) -> None:
        status = getattr(exc, "status", 400)
        self.send_json(status, {"error": {"code": exc.code, "message": exc.message}})

    def not_found(self) -> None:
        self.send_json(404, {"error": {"code": "not_found", "message": f"no route for {self.path}"}})

    def read_json_body(self) -> object:
        """Return the parsed JSON body, raising ValueError on malformed input."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        parts = urlsplit(self.path)
        if parts.path == COLLECTION_PATH:
            try:
                result = self.service.breakpoints.list(parts.query)
            except BreakpointError as exc:
                self.send_error_body(exc)
                return
            self.send_json(200, result)
            return
        self.not_found()

    def do_POST(self) -> None:
        # Frame routes keep the baseline's exact (query-less) path matching.
        if self.path == "/v1/frames/encode":
            handler: object = self.service.encode_frame
            status = 200
        elif self.path == "/v1/frames/decode":
            handler = self.service.decode_frame
            status = 200
        elif urlsplit(self.path).path == COLLECTION_PATH:
            handler = self.service.breakpoints.create
            status = 201
        else:
            self.not_found()
            return
        try:
            body = self.read_json_body()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(
                400, {"error": {"code": "invalid_request", "message": "request body is not valid JSON"}}
            )
            return
        try:
            result = handler(body)  # type: ignore[operator]
        except (FrameError, BreakpointError) as exc:
            self.send_error_body(exc)
            return
        self.send_json(status, result)

    def do_PATCH(self) -> None:
        parts = urlsplit(self.path)
        if not parts.path.startswith(ITEM_PREFIX):
            self.not_found()
            return
        try:
            body = self.read_json_body()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(
                400, {"error": {"code": "invalid_request", "message": "request body is not valid JSON"}}
            )
            return
        try:
            result = self.service.breakpoints.set_enabled(parts.path[len(ITEM_PREFIX) :], body)
        except BreakpointError as exc:
            self.send_error_body(exc)
            return
        self.send_json(200, result)

    def do_DELETE(self) -> None:
        parts = urlsplit(self.path)
        if not parts.path.startswith(ITEM_PREFIX):
            self.not_found()
            return
        try:
            result = self.service.breakpoints.delete(parts.path[len(ITEM_PREFIX) :])
        except BreakpointError as exc:
            self.send_error_body(exc)
            return
        self.send_json(200, result)

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence per-request logging so recorded output stays stable."""


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


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
