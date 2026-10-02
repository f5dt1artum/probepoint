"""Debug protocol frame codec (version 1).

Wire layout, all integers in network byte order (big-endian)::

    offset  size  field
    0       2     magic 0x5050
    2       1     version (1)
    3       1     flags
    4       4     sequence
    8       2     opcode
    10      2     payload length
    12      N     payload (0 <= N <= 4096)
    12+N    4     CRC-32/ISO-HDLC

The CRC covers every byte from the version field through the end of the
payload (i.e. everything except the magic and the CRC itself).
"""

from __future__ import annotations

import struct
import zlib

MAGIC = b"\x50\x50"
VERSION = 1
MAX_PAYLOAD = 4096

# magic(2s) version(B) flags(B) sequence(I) opcode(H) length(H)
_HEADER = struct.Struct(">2sBBIHH")
_CRC = struct.Struct(">I")
MIN_FRAME = _HEADER.size + _CRC.size  # 16 bytes, empty payload


class FrameError(Exception):
    """A frame could not be decoded; ``code`` is the public error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def encode(flags: int, sequence: int, opcode: int, payload: bytes) -> bytes:
    """Build a version-1 frame. Callers validate field ranges."""
    body = _HEADER.pack(MAGIC, VERSION, flags, sequence, opcode, len(payload)) + payload
    crc = zlib.crc32(body[len(MAGIC):]) & 0xFFFFFFFF
    return body + _CRC.pack(crc)


def decode(data: bytes) -> dict[str, object]:
    """Decode a frame, applying failure checks in their fixed priority."""
    if len(data) < MIN_FRAME:
        raise FrameError("truncated_frame", f"frame shorter than {MIN_FRAME} bytes")

    magic, version, flags, sequence, opcode, payload_len = _HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        raise FrameError("bad_magic", "frame magic is not 0x5050")
    if version != VERSION:
        raise FrameError("unsupported_version", f"unsupported frame version {version}")
    if payload_len > MAX_PAYLOAD:
        raise FrameError("invalid_length", f"payload length {payload_len} exceeds {MAX_PAYLOAD}")

    total = _HEADER.size + payload_len + _CRC.size
    if len(data) < total:
        raise FrameError("truncated_frame", "frame shorter than its declared payload length")
    if len(data) > total:
        raise FrameError("trailing_data", f"{len(data) - total} trailing byte(s) after frame")

    payload = data[_HEADER.size : _HEADER.size + payload_len]
    (crc_expected,) = _CRC.unpack_from(data, _HEADER.size + payload_len)
    crc_actual = zlib.crc32(data[len(MAGIC) : _HEADER.size + payload_len]) & 0xFFFFFFFF
    if crc_actual != crc_expected:
        raise FrameError("checksum_mismatch", "CRC-32 does not match")

    return {
        "version": version,
        "flags": flags,
        "sequence": sequence,
        "opcode": opcode,
        "payload": payload,
    }
