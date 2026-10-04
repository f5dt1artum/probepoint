"""In-process multi-target debug sessions (v1).

Sessions exist only in the service process: there is no persistence, so a
restart leaves no sessions. Each session owns an independent
:class:`~probepoint.breakpoints.BreakpointStore`; session ids grow
monotonically and are never reused.

Session deletion is atomic with respect to nested breakpoint operations: an
operation either runs to completion before the session is deleted, or fails
with ``session_not_found`` afterwards. A removed session (and its stores) can
never become reachable again.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .breakpoints import BreakpointStore

_MAX_NAME_LENGTH = 64
_ID_PATTERN = re.compile(r"[1-9][0-9]*\Z")


class SessionError(Exception):
    """Validation or lookup failure carrying the public error code/status."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def normalize_name(value: object) -> str:
    """Strip leading/trailing Unicode whitespace and validate the result."""
    if not isinstance(value, str):
        raise SessionError("invalid_field", "name must be a string")
    name = value.strip()
    if not name:
        raise SessionError("invalid_field", "name must not be empty")
    if len(name) > _MAX_NAME_LENGTH:
        raise SessionError(
            "invalid_field", f"name must be at most {_MAX_NAME_LENGTH} characters"
        )
    return name


def parse_session_create(body: object) -> str:
    """Validate a session create body, which must be ``{"name": str}``."""
    if not isinstance(body, dict):
        raise SessionError("invalid_request", "request body must be a JSON object")
    fields = body
    missing = {"name"} - fields.keys()
    if missing:
        raise SessionError("invalid_field", "missing field(s): name")
    extra = fields.keys() - {"name"}
    if extra:
        raise SessionError(
            "invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}"
        )
    return normalize_name(fields["name"])


def parse_session_id(raw: str) -> int:
    """Validate a positive decimal id without leading zeros."""
    if _ID_PATTERN.fullmatch(raw) is None:
        raise SessionError(
            "invalid_session_id", "session id must be a positive decimal integer"
        )
    return int(raw)


class Session:
    """A live session: metadata, its own breakpoint store and a guard."""

    __slots__ = ("id", "name", "breakpoints", "guard")

    def __init__(self, session_id: int, name: str) -> None:
        self.id = session_id
        self.name = name
        self.breakpoints = BreakpointStore()
        # Held for the whole of a nested operation (including reading the
        # request body), so deletion is strictly serialized with it.
        self.guard = threading.Lock()


class SessionStore:
    """Thread-safe, per-process session registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[int, Session] = {}
        self._names: dict[str, int] = {}
        self._next_id = 1

    def create(self, name: str) -> dict[str, object]:
        """Create a session; the normalized name is unique and case-sensitive."""
        with self._lock:
            if name in self._names:
                raise SessionError(
                    "duplicate_session", f"session named {name!r} already exists", 409
                )
            session_id = self._next_id
            self._next_id += 1
            session = Session(session_id, name)
            self._sessions[session_id] = session
            self._names[name] = session_id
            return {"id": session_id, "name": name}

    def list(self) -> list[dict[str, object]]:
        """Return live sessions in ascending id order."""
        with self._lock:
            return [
                {"id": session.id, "name": session.name}
                for session in self._sessions.values()
            ]

    def delete(self, session_id: int) -> dict[str, int]:
        """Atomically remove a session and drop all of its breakpoints.

        Waits for every in-flight operation on the session (anything inside
        :meth:`guard_session`) to finish, then unregisters the session and
        releases its name. Lock order is always guard-then-registry, matching
        :meth:`guard_session`, so the two cannot deadlock.
        """
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session_not_found", f"session {session_id} not found", 404
            )
        with session.guard:
            with self._lock:
                # A concurrent delete may have won while waiting for the guard.
                if session_id not in self._sessions:
                    raise SessionError(
                        "session_not_found", f"session {session_id} not found", 404
                    )
                del self._sessions[session_id]
                self._names.pop(session.name, None)
        return {"deleted": session_id}

    def _get(self, session_id: int) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionError(
                "session_not_found", f"session {session_id} not found", 404
            )
        return session

    @contextmanager
    def guard_session(self, session_id: int) -> Iterator[Session]:
        """Guard the whole handling of one nested operation.

        Resolves the session, then holds the session's guard for the duration
        of the ``with`` block (body reading, validation and store mutation
        included). A concurrent delete must acquire the same guard before it
        can unregister the session, so an operation either finishes completely
        before deletion or fails with ``session_not_found``. Different
        sessions use different guards and stay concurrent.
        """
        with self._lock:
            session = self._get(session_id)
        with session.guard:
            # Re-check under guard-then-registry: a delete may have removed
            # the session while this thread waited for the guard.
            with self._lock:
                self._get(session_id)
            yield session
