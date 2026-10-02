"""In-process breakpoint and watchpoint management (v1).

Records exist only in the service process: there is no persistence, so a
restart starts from an empty set. All public failures are reported via
:class:`BreakpointError`, whose ``code`` mirrors the documented error codes.
"""

from __future__ import annotations

import re
import threading
from urllib.parse import parse_qsl

VALID_KINDS = ("execute", "read", "write", "access")
_KIND_SET = frozenset(VALID_KINDS)
_VALID_SIZES = frozenset({1, 2, 4, 8})
_UINT32_MAX = (1 << 32) - 1

_CREATE_FIELDS = frozenset({"kind", "address", "enabled", "size"})
_REQUIRED_CREATE_FIELDS = frozenset({"kind", "address", "enabled"})
_PATCH_FIELDS = frozenset({"enabled"})

_ID_PATTERN = re.compile(r"[1-9][0-9]*\Z")


class BreakpointError(Exception):
    """Validation or lookup failure carrying the public error code/status."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _object(body: object) -> dict:
    if not isinstance(body, dict):
        raise BreakpointError("invalid_request", "request body must be a JSON object")
    return body


def parse_create(body: object) -> tuple[str, int, int | None, bool]:
    """Validate a create request; field errors take precedence over duplicates."""
    fields = _object(body)

    missing = _REQUIRED_CREATE_FIELDS - fields.keys()
    if missing:
        raise BreakpointError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    extra = fields.keys() - _CREATE_FIELDS
    if extra:
        raise BreakpointError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")

    kind = fields["kind"]
    if not isinstance(kind, str) or kind not in _KIND_SET:
        raise BreakpointError("invalid_field", "kind must be one of execute, read, write or access")

    address = fields["address"]
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address <= _UINT32_MAX:
        raise BreakpointError("invalid_field", "address must be an unsigned 32-bit integer")

    enabled = fields["enabled"]
    if not isinstance(enabled, bool):
        raise BreakpointError("invalid_field", "enabled must be a boolean")

    has_size = "size" in fields
    size: int | None = None
    if has_size:
        value = fields["size"]
        if isinstance(value, bool) or not isinstance(value, int) or value not in _VALID_SIZES:
            raise BreakpointError("invalid_field", "size must be one of 1, 2, 4 or 8")
        size = value

    if kind == "execute":
        if has_size:
            raise BreakpointError("invalid_field", "execute breakpoints must not carry size")
    else:
        if not has_size:
            raise BreakpointError("invalid_field", f"{kind} watchpoints require size")
        assert size is not None
        if address % size != 0:
            raise BreakpointError("invalid_field", f"address must be aligned to {size} bytes")

    return kind, address, size, enabled


def parse_patch(body: object) -> bool:
    """Validate a PATCH body, which may only toggle ``enabled``."""
    fields = _object(body)
    missing = _PATCH_FIELDS - fields.keys()
    if missing:
        raise BreakpointError("invalid_field", "missing field(s): enabled")
    extra = fields.keys() - _PATCH_FIELDS
    if extra:
        raise BreakpointError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    enabled = fields["enabled"]
    if not isinstance(enabled, bool):
        raise BreakpointError("invalid_field", "enabled must be a boolean")
    return enabled


def parse_list_query(query: str) -> tuple[str | None, bool | None]:
    """Parse the optional ``kind``/``enabled`` filters for GET collection."""
    kind: str | None = None
    enabled: bool | None = None
    seen: set[str] = set()
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key in seen:
            raise BreakpointError("invalid_query", f"duplicate query parameter: {key}")
        seen.add(key)
        if key == "kind":
            if value not in _KIND_SET:
                raise BreakpointError("invalid_query", "kind must be one of execute, read, write or access")
            kind = value
        elif key == "enabled":
            if value not in ("true", "false"):
                raise BreakpointError("invalid_query", "enabled must be true or false")
            enabled = value == "true"
        else:
            raise BreakpointError("invalid_query", f"unknown query parameter: {key}")
    return kind, enabled


def parse_breakpoint_id(raw: str) -> int:
    """Validate a positive decimal id path segment."""
    if _ID_PATTERN.fullmatch(raw) is None:
        raise BreakpointError("invalid_breakpoint_id", "breakpoint id must be a positive decimal integer")
    return int(raw)


class BreakpointStore:
    """Thread-safe, append-only (within the process) breakpoint records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[int, dict[str, object]] = {}
        self._next_id = 1

    def create(self, kind: str, address: int, size: int | None, enabled: bool) -> dict[str, object]:
        with self._lock:
            for record in self._records.values():
                if (
                    record["kind"] == kind
                    and record["address"] == address
                    and record.get("size") == size
                ):
                    raise BreakpointError(
                        "duplicate_breakpoint",
                        "a breakpoint with the same kind, address and size already exists",
                        409,
                    )
            record: dict[str, object] = {
                "id": self._next_id,
                "kind": kind,
                "address": address,
                "enabled": enabled,
            }
            if size is not None:
                record["size"] = size
            self._records[self._next_id] = record
            self._next_id += 1
            return dict(record)

    def list(self, kind: str | None = None, enabled: bool | None = None) -> list[dict[str, object]]:
        # Insertion order is id order because ids only ever grow.
        with self._lock:
            return [
                dict(record)
                for record in self._records.values()
                if (kind is None or record["kind"] == kind)
                and (enabled is None or record["enabled"] == enabled)
            ]

    def update(self, record_id: int, enabled: bool) -> dict[str, object]:
        with self._lock:
            record = self._records.get(record_id)
            if record is None:
                raise BreakpointError(
                    "breakpoint_not_found", f"breakpoint {record_id} not found", 404
                )
            record["enabled"] = enabled
            return dict(record)

    def delete(self, record_id: int) -> dict[str, int]:
        with self._lock:
            if record_id not in self._records:
                raise BreakpointError(
                    "breakpoint_not_found", f"breakpoint {record_id} not found", 404
                )
            del self._records[record_id]
            return {"deleted": record_id}
