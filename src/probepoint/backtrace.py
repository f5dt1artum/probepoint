"""Offline stack backtrace for ARM Cortex-M frame-pointer chains (v1).

Given a halt snapshot (register values plus a raw little-endian stack
capture), walk the 8-byte frame records emitted by ARM Thumb code built
with frame pointers: the word at the frame pointer holds the caller's
frame pointer, the next word the saved link register. The walk is purely
offline: it never connects to a target, keeps no session state and does
not touch breakpoint records.
"""

from __future__ import annotations

import struct

MAX_STACK_BYTES = 1 << 20  # 1 MiB snapshot cap
DEFAULT_MAX_FRAMES = 64
MAX_FRAMES_LIMIT = 256
_UINT32_MAX = (1 << 32) - 1
_ADDRESS_SPACE = 1 << 32

_REQUIRED_FIELDS = frozenset({"pc", "sp", "frame_pointer", "stack_base", "stack", "symbols"})
_OPTIONAL_FIELDS = frozenset({"max_frames"})
_SYMBOL_FIELDS = frozenset({"name", "start", "end"})
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

_RECORD = struct.Struct("<II")  # previous frame pointer, saved link register


class BacktraceError(Exception):
    """Validation failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint32(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BacktraceError("invalid_field", f"{field} must be an unsigned 32-bit integer")
    if value < 0 or value > _UINT32_MAX:
        raise BacktraceError("invalid_field", f"{field} out of range for unsigned 32-bit integer")
    return value


def _stack_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise BacktraceError("invalid_field", "stack must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise BacktraceError("invalid_field", "stack must be even-length hex without prefix or separators")
    data = bytes.fromhex(value)
    if len(data) > MAX_STACK_BYTES:
        raise BacktraceError("invalid_field", f"stack exceeds {MAX_STACK_BYTES} bytes")
    return data


def _parse_symbols(value: object) -> list[tuple[int, int, str]]:
    if not isinstance(value, list):
        raise BacktraceError("invalid_field", "symbols must be an array")
    symbols: list[tuple[int, int, str]] = []
    for index, entry in enumerate(value):
        field = f"symbols[{index}]"
        if not isinstance(entry, dict):
            raise BacktraceError("invalid_field", f"{field} must be an object")
        missing = _SYMBOL_FIELDS - entry.keys()
        if missing:
            raise BacktraceError(
                "invalid_field", f"{field} missing field(s): {', '.join(sorted(missing))}"
            )
        extra = entry.keys() - _SYMBOL_FIELDS
        if extra:
            raise BacktraceError(
                "invalid_field", f"{field} unexpected field(s): {', '.join(sorted(extra))}"
            )
        name = entry["name"]
        if not isinstance(name, str) or not name:
            raise BacktraceError("invalid_field", f"{field}.name must be a non-empty string")
        start = _uint32(entry["start"], f"{field}.start")
        end = _uint32(entry["end"], f"{field}.end")
        if start >= end:
            raise BacktraceError("invalid_field", f"{field} interval must satisfy start < end")
        symbols.append((start, end, name))
    ordered = sorted(symbols)
    for (prev_start, prev_end, _), (start, end, _) in zip(ordered, ordered[1:]):
        if start < prev_end:
            raise BacktraceError(
                "invalid_field",
                f"symbol intervals overlap: [{prev_start:#x}, {prev_end:#x}) and [{start:#x}, {end:#x})",
            )
    return symbols


def _parse_max_frames(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BacktraceError("invalid_field", "max_frames must be an integer")
    if value < 1 or value > MAX_FRAMES_LIMIT:
        raise BacktraceError("invalid_field", f"max_frames must be between 1 and {MAX_FRAMES_LIMIT}")
    return value


def _lookup(symbols: list[tuple[int, int, str]], address: int) -> tuple[str | None, int | None]:
    for start, end, name in symbols:
        if start <= address < end:
            return name, address - start
    return None, None


def backtrace(body: object) -> dict[str, object]:
    """Validate a backtrace request and unwind the frame-pointer chain."""
    if not isinstance(body, dict):
        raise BacktraceError("invalid_request", "request body must be a JSON object")
    missing = _REQUIRED_FIELDS - body.keys()
    if missing:
        raise BacktraceError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    extra = body.keys() - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
    if extra:
        raise BacktraceError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")

    pc = _uint32(body["pc"], "pc")
    sp = _uint32(body["sp"], "sp")
    frame_pointer = _uint32(body["frame_pointer"], "frame_pointer")
    stack_base = _uint32(body["stack_base"], "stack_base")
    stack = _stack_bytes(body["stack"])
    symbols = _parse_symbols(body["symbols"])
    max_frames = DEFAULT_MAX_FRAMES
    if "max_frames" in body:
        max_frames = _parse_max_frames(body["max_frames"])

    stack_end = stack_base + len(stack)  # one past the last covered byte
    if stack_end > _ADDRESS_SPACE:
        raise BacktraceError("invalid_field", "stack range extends past 0xffffffff")

    frames: list[dict[str, object]] = []

    def emit(level: int, address: int, frame_sp: int, frame_fp: int) -> None:
        symbol, offset = _lookup(symbols, address)
        frames.append(
            {
                "level": level,
                "address": address,
                "sp": frame_sp,
                "frame_pointer": frame_fp,
                "symbol": symbol,
                "offset": offset,
            }
        )

    emit(0, pc & ~1, sp, frame_pointer)

    fp = frame_pointer
    seen = {fp}
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
        if fp < stack_base or fp + _RECORD.size > stack_end:
            stop_reason = "stack_exhausted"
            break
        prev_fp, saved_lr = _RECORD.unpack(stack[fp - stack_base : fp - stack_base + _RECORD.size])
        if prev_fp == 0:
            stop_reason = "complete"
            break
        if prev_fp % 4 != 0 or prev_fp <= fp or prev_fp in seen:
            stop_reason = "invalid_chain"
            break
        seen.add(prev_fp)
        emit(len(frames), saved_lr & ~1, fp + _RECORD.size, prev_fp)
        fp = prev_fp

    return {"frames": frames, "stop_reason": stop_reason}
