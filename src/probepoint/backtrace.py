"""Offline stack backtrace for ARM Cortex-M frame-pointer chains (v1).

The unwinder works purely on a halted-state snapshot supplied in the
request: it never connects to a target, keeps no session state and does
not touch breakpoint records.  Each stack frame record is the classic
ARM little-endian 32-bit layout at the current frame pointer::

    fp + 0   previous frame pointer (4 bytes, little-endian)
    fp + 4   saved link register    (4 bytes, little-endian)

Frame 0 comes from the requested pc/sp/frame_pointer; every later frame
takes its address from the saved LR with the Thumb bit cleared and its
stack pointer as the record address plus 8.
"""

from __future__ import annotations

MAX_STACK = 1 << 20  # 1 MiB per backtrace request
DEFAULT_MAX_FRAMES = 64
MAX_FRAMES_LIMIT = 256
RECORD_LEN = 8  # saved frame pointer + saved link register
_UINT32_MAX = (1 << 32) - 1
_ADDRESS_SPACE = 1 << 32  # first address past 0xffffffff

_REQUIRED_FIELDS = frozenset({"pc", "sp", "frame_pointer", "stack_base", "stack", "symbols"})
_OPTIONAL_FIELDS = frozenset({"max_frames"})
_SYMBOL_FIELDS = frozenset({"name", "start", "end"})

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


class BacktraceError(Exception):
    """Validation failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BacktraceError("invalid_field", f"{field} must be an unsigned 32-bit integer")
    if value < 0 or value > _UINT32_MAX:
        raise BacktraceError("invalid_field", f"{field} out of range for unsigned 32-bit integer")
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise BacktraceError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise BacktraceError(
            "invalid_field", f"{field} must be even-length hex without prefix or separators"
        )
    return bytes.fromhex(value)


def _check_fields(body: object) -> dict:
    if not isinstance(body, dict):
        raise BacktraceError("invalid_request", "request body must be a JSON object")
    missing = _REQUIRED_FIELDS - body.keys()
    extra = body.keys() - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
    if missing:
        raise BacktraceError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise BacktraceError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def _parse_symbols(value: object) -> list[tuple[int, int, str]]:
    """Validate the symbol table and return it sorted by start address."""
    if not isinstance(value, list):
        raise BacktraceError("invalid_field", "symbols must be an array")
    symbols: list[tuple[int, int, str]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise BacktraceError("invalid_field", "each symbol must be a JSON object")
        missing = _SYMBOL_FIELDS - entry.keys()
        extra = entry.keys() - _SYMBOL_FIELDS
        if missing:
            raise BacktraceError(
                "invalid_field", f"symbol missing field(s): {', '.join(sorted(missing))}"
            )
        if extra:
            raise BacktraceError(
                "invalid_field", f"symbol has unexpected field(s): {', '.join(sorted(extra))}"
            )
        name = entry["name"]
        if not isinstance(name, str) or not name:
            raise BacktraceError("invalid_field", "symbol name must be a non-empty string")
        start = _uint(entry["start"], "symbol start")
        end = _uint(entry["end"], "symbol end")
        if start >= end:
            raise BacktraceError("invalid_field", "symbol start must be less than symbol end")
        symbols.append((start, end, name))
    symbols.sort(key=lambda item: item[0])
    for previous, current in zip(symbols, symbols[1:]):
        if current[0] < previous[1]:
            raise BacktraceError("invalid_field", "symbol ranges must not overlap")
    return symbols


def _lookup(symbols: list[tuple[int, int, str]], address: int) -> tuple[str | None, int | None]:
    for start, end, name in symbols:
        if start <= address < end:
            return name, address - start
    return None, None


def _frame(
    level: int, address: int, sp: int, frame_pointer: int, symbols: list[tuple[int, int, str]]
) -> dict[str, object]:
    symbol, offset = _lookup(symbols, address)
    return {
        "level": level,
        "address": address,
        "sp": sp,
        "frame_pointer": frame_pointer,
        "symbol": symbol,
        "offset": offset,
    }


def backtrace(body: object) -> dict[str, object]:
    """Validate a backtrace request and unwind the frame-pointer chain.

    Returns ``{"frames": [...], "stop_reason": ...}``.  Unwinding stops
    with ``complete`` when the frame pointer reaches zero, ``max_frames``
    when the frame limit is hit, ``invalid_chain`` when a pointer is
    misaligned or the chain fails to advance strictly upward (including
    cycles), and ``stack_exhausted`` when a record does not fall fully
    inside the snapshot.  Partial frames are never emitted: a frame is
    only appended once its record has been read and validated.
    """
    fields = _check_fields(body)
    pc = _uint(fields["pc"], "pc")
    sp = _uint(fields["sp"], "sp")
    frame_pointer = _uint(fields["frame_pointer"], "frame_pointer")
    stack_base = _uint(fields["stack_base"], "stack_base")

    stack = _hex_bytes(fields["stack"], "stack")
    if len(stack) > MAX_STACK:
        raise BacktraceError("invalid_field", f"stack exceeds {MAX_STACK} decoded bytes")
    if stack_base + len(stack) > _ADDRESS_SPACE:
        raise BacktraceError(
            "invalid_field", "stack_base + stack length crosses the end of the 32-bit address space"
        )

    max_frames = fields.get("max_frames", DEFAULT_MAX_FRAMES)
    if not isinstance(max_frames, int) or isinstance(max_frames, bool):
        raise BacktraceError("invalid_field", "max_frames must be an integer")
    if not 1 <= max_frames <= MAX_FRAMES_LIMIT:
        raise BacktraceError(
            "invalid_field", f"max_frames must be between 1 and {MAX_FRAMES_LIMIT}"
        )

    symbols = _parse_symbols(fields["symbols"])

    frames: list[dict[str, object]] = [
        _frame(0, pc & ~1, sp, frame_pointer, symbols)
    ]
    fp = frame_pointer
    while True:
        if fp == 0:
            stop_reason = "complete"
            break
        if len(frames) >= max_frames:
            stop_reason = "max_frames"
            break
        if fp % 4 != 0:
            stop_reason = "invalid_chain"
            break
        offset = fp - stack_base
        if offset < 0 or offset + RECORD_LEN > len(stack):
            stop_reason = "stack_exhausted"
            break
        record = stack[offset : offset + RECORD_LEN]
        previous_fp = int.from_bytes(record[:4], "little")
        saved_lr = int.from_bytes(record[4:], "little")
        if previous_fp != 0 and previous_fp <= fp:
            # The chain must advance strictly toward higher addresses;
            # this also rules out cycles.
            stop_reason = "invalid_chain"
            break
        frames.append(_frame(len(frames), saved_lr & ~1, fp + RECORD_LEN, previous_fp, symbols))
        fp = previous_fp

    return {"frames": frames, "stop_reason": stop_reason}
