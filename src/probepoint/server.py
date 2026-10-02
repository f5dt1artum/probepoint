"""HTTP entry point for ProbePoint."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import Service, ServiceError


def env_address() -> tuple[str, int]:
    raw = os.environ.get("PROBEPOINT_ADDR", "127.0.0.1:8080")
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"invalid PROBEPOINT_ADDR: {raw!r}")
    return host, int(port)


class Handler(BaseHTTPRequestHandler):
    service = Service()

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, code: str, message: str) -> None:
        self.send_json(status, {"error": {"code": code, "message": message}})

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        self.send_error_json(404, "not_found", f"no route for {self.path}")

    def do_POST(self) -> None:
        if self.path not in ("/v1/frames/encode", "/v1/frames/decode"):
            self.send_error_json(404, "not_found", f"no route for {self.path}")
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error_json(400, "invalid_request", "request body must be a JSON object")
            return
        if not isinstance(request, dict):
            self.send_error_json(400, "invalid_request", "request body must be a JSON object")
            return

        try:
            if self.path == "/v1/frames/encode":
                response = self.service.encode_frame(request)
            else:
                response = self.service.decode_frame(request)
        except ServiceError as exc:
            self.send_error_json(400, exc.code, str(exc))
            return
        self.send_json(200, response)

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence per-request logging so recorded output stays stable."""


def main() -> int:
    parser = argparse.ArgumentParser(prog="probepoint.server", description="嵌入式调试与探针工具")
    host, port = env_address()
    parser.add_argument("--host", default=host)
    parser.add_argument("--port", type=int, default=port)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
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
