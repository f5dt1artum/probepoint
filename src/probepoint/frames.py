"""Debug protocol frame codec (version 1).

Frame layout, network byte order::

    magic    2 bytes   0x5050
    version  1 byte    1
    flags    1 byte
    sequence 4 bytes
    opcode   2 bytes
    length   2 bytes   payload length in bytes
    payload  0..4096 bytes
    crc32    4 bytes   CRC-32/ISO-HDLC over version..payload (inclusive)
"""

from __future__ import annotations

import struct
import zlib

MAGIC = 0x5050
VERSION = 1
MAX_PAYLOAD = 4096
MAX_STREAM_DATA = 1 << 20  # 1 MiB per decode-stream request

HEADER_LEN = 12  # magic(2) version(1) flags(1) sequence(4) opcode(2) length(2)
CRC_LEN = 4
MIN_FRAME_LEN = HEADER_LEN + CRC_LEN

_HEADER = struct.Struct(">HBBIHH")
_UINT32 = struct.Struct(">I")

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


class FrameError(Exception):
    """Validation or codec failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint(value: object, bits: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FrameError("invalid_field", f"{field} must be an unsigned {bits}-bit integer")
    if value < 0 or value >= 1 << bits:
        raise FrameError("invalid_field", f"{field} out of range for unsigned {bits}-bit integer")
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise FrameError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise FrameError("invalid_field", f"{field} must be even-length hex without prefix or separators")
    return bytes.fromhex(value)


def _check_fields(body: object, expected: frozenset[str]) -> dict:
    if not isinstance(body, dict):
        raise FrameError("invalid_request", "request body must be a JSON object")
    missing = expected - body.keys()
    extra = body.keys() - expected
    if missing:
        raise FrameError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise FrameError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def encode_frame(body: object) -> dict[str, str]:
    """Validate an encode request and return {"frame": <lowercase hex>}."""
    fields = _check_fields(body, frozenset({"flags", "sequence", "opcode", "payload"}))
    flags = _uint(fields["flags"], 8, "flags")
    sequence = _uint(fields["sequence"], 32, "sequence")
    opcode = _uint(fields["opcode"], 16, "opcode")
    payload = _hex_bytes(fields["payload"], "payload")
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("invalid_field", f"payload exceeds {MAX_PAYLOAD} bytes")

    header = _HEADER.pack(MAGIC, VERSION, flags, sequence, opcode, len(payload))
    crc = zlib.crc32(header[2:] + payload)
    frame = header + payload + _UINT32.pack(crc)
    return {"frame": frame.hex()}


def decode_frame(body: object) -> dict[str, object]:
    """Validate a decode request and return the parsed frame fields."""
    fields = _check_fields(body, frozenset({"frame"}))
    data = _hex_bytes(fields["frame"], "frame")

    if len(data) < MIN_FRAME_LEN:
        raise FrameError("truncated_frame", f"frame shorter than minimum {MIN_FRAME_LEN} bytes")
    magic, version, flags, sequence, opcode, length = _HEADER.unpack(data[:HEADER_LEN])
    if magic != MAGIC:
        raise FrameError("bad_magic", f"magic 0x{magic:04x} != 0x{MAGIC:04x}")
    if version != VERSION:
        raise FrameError("unsupported_version", f"version {version} is not supported")
    if length > MAX_PAYLOAD:
        raise FrameError("invalid_length", f"declared payload length {length} exceeds {MAX_PAYLOAD}")
    total = HEADER_LEN + length + CRC_LEN
    if len(data) < total:
        raise FrameError("truncated_frame", f"frame has {len(data)} bytes, expected {total}")
    if len(data) > total:
        raise FrameError("trailing_data", f"frame has {len(data) - total} extra byte(s)")

    payload = data[HEADER_LEN : HEADER_LEN + length]
    (crc_expected,) = _UINT32.unpack(data[HEADER_LEN + length : total])
    crc_actual = zlib.crc32(data[2 : HEADER_LEN + length])
    if crc_actual != crc_expected:
        raise FrameError("checksum_mismatch", "CRC-32/ISO-HDLC mismatch")

    return {
        "version": version,
        "flags": flags,
        "sequence": sequence,
        "opcode": opcode,
        "payload": payload.hex(),
    }


def decode_stream(body: object) -> dict[str, object]:
    """Validate a decode-stream request and scan one stateless byte fragment.

    The fragment carries no session state: callers resubmit the previously
    returned ``remainder`` concatenated with fresh bytes. Frames and errors
    are reported as they appear; bytes that start no frame are counted as
    ``discarded`` unless they may still complete with future data, in which
    case they form the ``remainder``.
    """
    fields = _check_fields(body, frozenset({"data", "eof"}))
    if not isinstance(fields["eof"], bool):
        raise FrameError("invalid_field", "eof must be a boolean")
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_STREAM_DATA:
        raise FrameError("invalid_field", f"data exceeds {MAX_STREAM_DATA} decoded bytes")

    frames: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    discarded = 0

    n = len(data)
    i = 0
    while i < n:
        # Find the next magic candidate; preceding bytes are line noise.
        if data[i] != 0x50:
            discarded += 1
            i += 1
            continue
        if i + 1 >= n:
            # Lone trailing 0x50: keep it as a potential magic start while
            # more bytes may arrive; at end of stream it is a truncated
            # candidate rather than plain noise.
            if fields["eof"]:
                errors.append({"offset": i, "code": "truncated_frame"})
                discarded += 1
                i += 1
            break
        if data[i + 1] != 0x50:
            discarded += 1
            i += 1
            continue

        offset = i

        # A full header is needed to learn the declared payload length.
        if n - i < HEADER_LEN:
            if fields["eof"]:
                errors.append({"offset": offset, "code": "truncated_frame"})
                discarded += n - i
                i = n
            else:
                # Candidate might complete once more bytes arrive.
                break
            continue

        _magic, version, _flags, _sequence, _opcode, length = _HEADER.unpack(
            data[i : i + HEADER_LEN]
        )
        if version != VERSION:
            # Deterministic header failure: resync one byte past the magic.
            errors.append({"offset": offset, "code": "unsupported_version"})
            discarded += 1
            i += 1
            continue
        if length > MAX_PAYLOAD:
            errors.append({"offset": offset, "code": "invalid_length"})
            discarded += 1
            i += 1
            continue

        total = HEADER_LEN + length + CRC_LEN
        if n - i < total:
            if fields["eof"]:
                errors.append({"offset": offset, "code": "truncated_frame"})
                discarded += n - i
                i = n
            else:
                # Wait for the declared payload and CRC before judging it.
                break
            continue

        chunk = data[i : i + total]
        (crc_expected,) = _UINT32.unpack(chunk[HEADER_LEN + length : total])
        crc_actual = zlib.crc32(chunk[2 : HEADER_LEN + length])
        if crc_actual != crc_expected:
            errors.append({"offset": offset, "code": "checksum_mismatch"})
            discarded += 1
            i += 1
            continue

        frames.append(
            {
                "offset": offset,
                "version": version,
                "flags": _flags,
                "sequence": _sequence,
                "opcode": _opcode,
                "payload": chunk[HEADER_LEN : HEADER_LEN + length].hex(),
            }
        )
        i += total

    remainder = data[i:] if not fields["eof"] else b""
    return {
        "frames": frames,
        "errors": errors,
        "discarded": discarded,
        "remainder": remainder.hex(),
    }
