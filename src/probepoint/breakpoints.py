"""In-process breakpoint and watchpoint management for the v1 HTTP API.

Records live only in the owning process: there is no persistence, and ids
are allocated from a per-process monotonic counter that is never reused,
even after a record is deleted.
"""

from __future__ import annotations

import threading
from urllib.parse import parse_qsl

KINDS = ("execute", "read", "write", "access")
WATCH_KINDS = ("read", "write", "access")
SIZES = (1, 2, 4, 8)
MAX_ADDRESS = 0xFFFFFFFF

_ALL_FIELDS = frozenset({"kind", "address", "enabled", "size"})
_BASE_FIELDS = frozenset({"kind", "address", "enabled"})
_QUERY_PARAMS = frozenset({"kind", "enabled"})


class BreakpointError(Exception):
    """Validation or lookup failure carrying the public error code/status."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _as_object(body: object) -> dict:
    if not isinstance(body, dict):
        raise BreakpointError("invalid_request", "request body must be a JSON object")
    return body


def validate_breakpoint(body: object) -> tuple[str, int, int | None, bool]:
    """Validate a create request; field errors precede any duplicate check."""
    fields = _as_object(body)
    extra = set(fields) - _ALL_FIELDS
    if extra:
        raise BreakpointError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    missing = _BASE_FIELDS - fields.keys()
    if missing:
        raise BreakpointError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")

    kind = fields["kind"]
    if not isinstance(kind, str) or kind not in KINDS:
        raise BreakpointError(
            "invalid_field", "kind must be one of execute, read, write or access"
        )

    address = fields["address"]
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address <= MAX_ADDRESS:
        raise BreakpointError(
            "invalid_field", "address must be an unsigned 32-bit integer"
        )

    enabled = fields["enabled"]
    if not isinstance(enabled, bool):
        raise BreakpointError("invalid_field", "enabled must be a boolean")

    if kind == "execute":
        if "size" in fields:
            raise BreakpointError("invalid_field", "execute breakpoints must not carry size")
        size: int | None = None
    else:
        if "size" not in fields:
            raise BreakpointError("invalid_field", f"{kind} watchpoints require a size")
        size = fields["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size not in SIZES:
            raise BreakpointError("invalid_field", "size must be one of 1, 2, 4 or 8")
        if address % size != 0:
            raise BreakpointError("invalid_field", f"address must be aligned to {size} bytes")

    return kind, address, size, enabled


def validate_enabled(body: object) -> bool:
    """Validate a PATCH body, which may only toggle enabled."""
    fields = _as_object(body)
    extra = set(fields) - {"enabled"}
    if extra:
        raise BreakpointError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    if "enabled" not in fields:
        raise BreakpointError("invalid_field", "missing field(s): enabled")
    enabled = fields["enabled"]
    if not isinstance(enabled, bool):
        raise BreakpointError("invalid_field", "enabled must be a boolean")
    return enabled


def parse_breakpoint_id(raw: str) -> int:
    """Parse a positive decimal id from a URL path segment."""
    if not raw or not raw.isdigit():
        raise BreakpointError(
            "invalid_breakpoint_id", "breakpoint id must be a positive decimal integer"
        )
    value = int(raw)
    if value < 1:
        raise BreakpointError(
            "invalid_breakpoint_id", "breakpoint id must be a positive decimal integer"
        )
    return value


def parse_filters(query: str) -> dict[str, object]:
    """Validate the kind/enabled query parameters of the collection endpoint."""
    filters: dict[str, object] = {}
    seen: set[str] = set()
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key not in _QUERY_PARAMS:
            raise BreakpointError("invalid_query", f"unknown query parameter: {key}")
        if key in seen:
            raise BreakpointError("invalid_query", f"query parameter repeated: {key}")
        seen.add(key)
        if key == "kind":
            if value not in KINDS:
                raise BreakpointError(
                    "invalid_query", "kind must be one of execute, read, write or access"
                )
            filters["kind"] = value
        else:
            if value not in ("true", "false"):
                raise BreakpointError("invalid_query", "enabled must be true or false")
            filters["enabled"] = value == "true"
    return filters


class BreakpointStore:
    """Thread-safe, process-local collection of breakpoint records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[int, dict[str, object]] = {}
        self._next_id = 1

    def create(self, body: object) -> dict[str, object]:
        kind, address, size, enabled = validate_breakpoint(body)
        with self._lock:
            for record in self._records.values():
                if (
                    record["kind"] == kind
                    and record["address"] == address
                    and record["size"] == size
                ):
                    raise BreakpointError(
                        "duplicate_breakpoint",
                        "a breakpoint with the same kind, address and size already exists",
                        status=409,
                    )
            record_id = self._next_id
            record = {
                "id": record_id,
                "kind": kind,
                "address": address,
                "size": size,
                "enabled": enabled,
            }
            self._records[record_id] = record
            self._next_id += 1
            return dict(record)

    def list(self, query: str) -> list[dict[str, object]]:
        filters = parse_filters(query)
        with self._lock:
            records = sorted(self._records.values(), key=lambda r: int(r["id"]))
            return [dict(r) for r in records if self._matches(r, filters)]

    @staticmethod
    def _matches(record: dict[str, object], filters: dict[str, object]) -> bool:
        if "kind" in filters and record["kind"] != filters["kind"]:
            return False
        if "enabled" in filters and record["enabled"] != filters["enabled"]:
            return False
        return True

    def set_enabled(self, raw_id: str, body: object) -> dict[str, object]:
        record_id = parse_breakpoint_id(raw_id)
        enabled = validate_enabled(body)
        with self._lock:
            record = self._records.get(record_id)
            if record is None:
                raise BreakpointError(
                    "breakpoint_not_found", f"no breakpoint with id {record_id}", status=404
                )
            record["enabled"] = enabled
            return dict(record)

    def delete(self, raw_id: str) -> dict[str, int]:
        record_id = parse_breakpoint_id(raw_id)
        with self._lock:
            if record_id not in self._records:
                raise BreakpointError(
                    "breakpoint_not_found", f"no breakpoint with id {record_id}", status=404
                )
            del self._records[record_id]
            return {"deleted": record_id}
