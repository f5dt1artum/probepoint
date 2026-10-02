"""Core service surface for ProbePoint.

The frozen baseline reports process health. The debug protocol frame
codec (version 1) lives behind the same service so the public surface
stays in one place.
"""

from __future__ import annotations

from . import __version__
from . import frames
from .frames import FrameError

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


class ServiceError(Exception):
    """A client request was invalid; ``code`` is the public error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _is_uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _uint_field(obj: dict, name: str, bits: int) -> int:
    try:
        value = obj[name]
    except KeyError:
        raise ServiceError("invalid_field", f"missing field: {name}") from None
    if not _is_uint(value):
        raise ServiceError("invalid_field", f"field {name} must be an unsigned integer")
    maximum = (1 << bits) - 1
    if not 0 <= value <= maximum:
        raise ServiceError("invalid_field", f"field {name} out of range for uint{bits}")
    return value


def _hex_field(obj: dict, name: str, *, allow_empty: bool) -> bytes:
    try:
        value = obj[name]
    except KeyError:
        raise ServiceError("invalid_field", f"missing field: {name}") from None
    if not isinstance(value, str):
        raise ServiceError("invalid_field", f"field {name} must be a hexadecimal string")
    if len(value) % 2 != 0 or any(c not in _HEX_CHARS for c in value):
        raise ServiceError("invalid_field", f"field {name} must be an even-length hexadecimal string")
    if not allow_empty and not value:
        raise ServiceError("invalid_field", f"field {name} must not be empty")
    return bytes.fromhex(value)


class Service:
    """Health reporting plus the version-1 debug frame codec."""

    name = "probepoint"
    version = __version__

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def encode_frame(self, request: dict) -> dict[str, str]:
        expected = {"flags", "sequence", "opcode", "payload"}
        if set(request) != expected:
            raise ServiceError("invalid_field", "encode request must contain exactly flags, sequence, opcode, payload")
        flags = _uint_field(request, "flags", 8)
        sequence = _uint_field(request, "sequence", 32)
        opcode = _uint_field(request, "opcode", 16)
        payload = _hex_field(request, "payload", allow_empty=True)
        if len(payload) > frames.MAX_PAYLOAD:
            raise ServiceError("invalid_field", f"payload exceeds {frames.MAX_PAYLOAD} bytes")
        frame = frames.encode(flags, sequence, opcode, payload)
        return {"frame": frame.hex()}

    def decode_frame(self, request: dict) -> dict[str, object]:
        if set(request) != {"frame"}:
            raise ServiceError("invalid_field", "decode request must contain exactly frame")
        data = _hex_field(request, "frame", allow_empty=True)
        try:
            decoded = frames.decode(data)
        except FrameError as exc:
            raise ServiceError(exc.code, str(exc)) from None
        return {
            "version": decoded["version"],
            "flags": decoded["flags"],
            "sequence": decoded["sequence"],
            "opcode": decoded["opcode"],
            "payload": decoded["payload"].hex(),
        }
