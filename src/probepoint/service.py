"""Core service surface for ProbePoint.

The frozen baseline reports process health and exposes the v1 frame codec.
Breakpoint/watchpoint management lives in :mod:`probepoint.breakpoints`;
records are process-local and never persisted. The GDB RSP packet codec
lives in :mod:`probepoint.rsp`. Keep the public surface here backward
compatible.
"""

from __future__ import annotations

from . import __version__, rsp
from .breakpoints import (
    BreakpointStore,
    parse_create,
    parse_list_query,
    parse_patch,
)
from .frames import decode_frame, decode_stream, encode_frame


class Service:
    """Health reporting, the v1 frame codec and in-process breakpoints."""

    name = "probepoint"
    version = __version__

    def __init__(self) -> None:
        self.breakpoints = BreakpointStore()

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def encode_frame(self, body: object) -> dict[str, str]:
        return encode_frame(body)

    def decode_frame(self, body: object) -> dict[str, object]:
        return decode_frame(body)

    def decode_stream(self, body: object) -> dict[str, object]:
        return decode_stream(body)

    def encode_rsp(self, body: object) -> dict[str, str]:
        return rsp.encode_packet(body)

    def decode_rsp_stream(self, body: object) -> dict[str, object]:
        return rsp.decode_stream(body)

    def create_breakpoint(self, body: object) -> dict[str, object]:
        kind, address, size, enabled = parse_create(body)
        return self.breakpoints.create(kind, address, size, enabled)

    def list_breakpoints(self, query: str) -> list[dict[str, object]]:
        kind, enabled = parse_list_query(query)
        return self.breakpoints.list(kind, enabled)

    def update_breakpoint(self, record_id: int, body: object) -> dict[str, object]:
        return self.breakpoints.update(record_id, parse_patch(body))

    def delete_breakpoint(self, record_id: int) -> dict[str, int]:
        return self.breakpoints.delete(record_id)
