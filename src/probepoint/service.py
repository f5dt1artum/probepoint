"""Core service surface for ProbePoint.

The frozen baseline reports process health and exposes the v1 frame codec.
Breakpoint/watchpoint management lives in :mod:`probepoint.breakpoints`;
multi-target sessions live in :mod:`probepoint.sessions`. Records are
process-local and never persisted. Keep the public surface here backward
compatible.
"""

from __future__ import annotations

from . import __version__
from .backtrace import backtrace
from .breakpoints import (
    BreakpointStore,
    parse_create,
    parse_list_query,
    parse_patch,
)
from .channels import decode_channel_stream, encode_channel
from .faults import analyze_cortex_m_fault
from .frames import decode_frame, decode_stream, encode_frame
from .itm import decode_stream as itm_decode_stream
from .performance import analyze_cycles
from .rsp import decode_command_response
from .rsp import decode_stream as rsp_decode_stream
from .rsp import encode_command
from .rsp import encode_packet
from .sessions import SessionStore
from .sessions import parse_create as parse_session_create
from .symbols import resolve_symbols


class Service:
    """Health reporting, frame/RSP codecs, breakpoints and sessions."""

    name = "probepoint"
    version = __version__

    def __init__(self) -> None:
        self.breakpoints = BreakpointStore()
        self.sessions = SessionStore()

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def encode_frame(self, body: object) -> dict[str, str]:
        return encode_frame(body)

    def decode_frame(self, body: object) -> dict[str, object]:
        return decode_frame(body)

    def decode_stream(self, body: object) -> dict[str, object]:
        return decode_stream(body)

    def encode_channel(self, body: object) -> dict[str, str]:
        return encode_channel(body)

    def decode_channel_stream(self, body: object) -> dict[str, object]:
        return decode_channel_stream(body)

    def decode_itm_stream(self, body: object) -> dict[str, object]:
        return itm_decode_stream(body)

    def encode_rsp_packet(self, body: object) -> dict[str, str]:
        return encode_packet(body)

    def decode_rsp_stream(self, body: object) -> dict[str, object]:
        return rsp_decode_stream(body)

    def encode_rsp_command(self, body: object) -> dict[str, str]:
        return encode_command(body)

    def decode_rsp_command_response(self, body: object) -> dict[str, object]:
        return decode_command_response(body)

    def backtrace(self, body: object) -> dict[str, object]:
        return backtrace(body)

    def resolve_symbols(self, body: object) -> dict[str, object]:
        return resolve_symbols(body)

    def analyze_cycles(self, body: object) -> dict[str, object]:
        return analyze_cycles(body)

    def analyze_cortex_m_fault(self, body: object) -> dict[str, object]:
        return analyze_cortex_m_fault(body)

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

    def create_session(self, body: object) -> dict[str, object]:
        return self.sessions.create(parse_session_create(body))

    def list_sessions(self) -> list[dict[str, object]]:
        return self.sessions.list()

    def delete_session(self, session_id: int) -> dict[str, int]:
        return self.sessions.delete(session_id)

    def require_session(self, session_id: int) -> None:
        self.sessions.require(session_id)

    def create_session_breakpoint(self, session_id: int, body: object) -> dict[str, object]:
        kind, address, size, enabled = parse_create(body)
        return self.sessions.create_breakpoint(session_id, kind, address, size, enabled)

    def list_session_breakpoints(self, session_id: int, query: str) -> list[dict[str, object]]:
        kind, enabled = parse_list_query(query)
        return self.sessions.list_breakpoints(session_id, kind, enabled)

    def update_session_breakpoint(
        self, session_id: int, record_id: int, body: object
    ) -> dict[str, object]:
        return self.sessions.update_breakpoint(session_id, record_id, parse_patch(body))

    def delete_session_breakpoint(self, session_id: int, record_id: int) -> dict[str, int]:
        return self.sessions.delete_breakpoint(session_id, record_id)
