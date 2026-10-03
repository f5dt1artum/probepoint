"""In-process multi-target debug sessions (v1).

Sessions exist only in the service process: a restart starts from an empty
set and nothing is persisted. Each session owns an independent
:class:`~probepoint.breakpoints.BreakpointStore`, so breakpoint ids restart
from 1 per session and identical records may live in different sessions.
All public failures are reported via :class:`SessionError`, whose ``code``
mirrors the documented error codes.
"""

from __future__ import annotations

import re
import threading

from .breakpoints import BreakpointStore

_ID_PATTERN = re.compile(r"[1-9][0-9]*\Z")
_MAX_NAME_LENGTH = 64

_CREATE_FIELDS = frozenset({"name"})


class SessionError(Exception):
    """Validation or lookup failure carrying the public error code/status."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def parse_session_id(raw: str) -> int:
    """Validate a positive decimal id path segment (no leading zeros)."""
    if _ID_PATTERN.fullmatch(raw) is None:
        raise SessionError(
            "invalid_session_id", "session id must be a positive decimal integer"
        )
    return int(raw)


def parse_create(body: object) -> str:
    """Validate a create request and return the normalized session name."""
    if not isinstance(body, dict):
        raise SessionError("invalid_request", "request body must be a JSON object")

    missing = _CREATE_FIELDS - body.keys()
    if missing:
        raise SessionError("invalid_field", "missing field(s): name")
    extra = body.keys() - _CREATE_FIELDS
    if extra:
        raise SessionError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")

    name = body["name"]
    if not isinstance(name, str):
        raise SessionError("invalid_field", "name must be a string")

    normalized = name.strip()
    if not normalized:
        raise SessionError("invalid_field", "name must not be empty after trimming whitespace")
    if len(normalized) > _MAX_NAME_LENGTH:
        raise SessionError("invalid_field", "name must be at most 64 characters")
    return normalized


class _Session:
    """One live session: a normalized name plus its private breakpoint store."""

    def __init__(self, session_id: int, name: str) -> None:
        self.id = session_id
        self.name = name
        self.breakpoints = BreakpointStore()


class SessionStore:
    """Thread-safe registry of live sessions and their breakpoint stores."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[int, _Session] = {}
        self._names: set[str] = set()
        self._next_id = 1

    def create(self, name: str) -> dict[str, object]:
        with self._lock:
            if name in self._names:
                raise SessionError(
                    "duplicate_session", f"a session named {name!r} already exists", 409
                )
            session_id = self._next_id
            self._next_id += 1
            self._sessions[session_id] = _Session(session_id, name)
            self._names.add(name)
            return {"id": session_id, "name": name}

    def list(self) -> list[dict[str, object]]:
        # Insertion order is id order because ids only ever grow.
        with self._lock:
            return [
                {"id": session.id, "name": session.name}
                for session in self._sessions.values()
            ]

    def delete(self, session_id: int) -> dict[str, int]:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                raise SessionError(
                    "session_not_found", f"session {session_id} not found", 404
                )
            self._names.discard(session.name)
            # Dropping the only reference atomically discards its breakpoints.
            return {"deleted": session_id}

    def require(self, session_id: int) -> None:
        """Pre-check so requests against deleted sessions fail before body parsing."""
        with self._lock:
            self._get(session_id)

    def _get(self, session_id: int) -> _Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session_not_found", f"session {session_id} not found", 404
            )
        return session

    # Nested breakpoint operations run under the registry lock so a
    # concurrent session delete either happens entirely before them or
    # leaves them facing session_not_found; deleted data never resurfaces.

    def create_breakpoint(
        self, session_id: int, kind: str, address: int, size: int | None, enabled: bool
    ) -> dict[str, object]:
        with self._lock:
            return self._get(session_id).breakpoints.create(kind, address, size, enabled)

    def list_breakpoints(
        self, session_id: int, kind: str | None = None, enabled: bool | None = None
    ) -> list[dict[str, object]]:
        with self._lock:
            return self._get(session_id).breakpoints.list(kind, enabled)

    def update_breakpoint(
        self, session_id: int, record_id: int, enabled: bool
    ) -> dict[str, object]:
        with self._lock:
            return self._get(session_id).breakpoints.update(record_id, enabled)

    def delete_breakpoint(self, session_id: int, record_id: int) -> dict[str, int]:
        with self._lock:
            return self._get(session_id).breakpoints.delete(record_id)
