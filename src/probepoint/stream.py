"""Stateless stream decoder for v1 debug protocol frames.

Handles arbitrary byte segments from serial or TCP links: complete frames are
returned in order of appearance, noise is counted as ``discarded`` and an
incomplete tail is returned as ``remainder`` so the caller can prepend it to
the next chunk. The server keeps no session state between requests.
"""

from __future__ import annotations

import zlib

from .frames import (
    CRC_LEN,
    HEADER_LEN,
    MAX_PAYLOAD,
    VERSION,
    FrameError,
    _check_fields,
    _HEADER,
    _hex_bytes,
    _UINT32,
)

MAX_STREAM_DATA = 1 << 20  # 1048576 decoded bytes per request

_MAGIC = b"\x50\x50"
_MAGIC_FIRST_BYTE = 0x50

_FIELDS = frozenset({"data", "eof"})


def decode_stream(body: object) -> dict[str, object]:
    """Validate a decode-stream request and scan ``data`` for v1 frames."""
    fields = _check_fields(body, _FIELDS)
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_STREAM_DATA:
        raise FrameError("invalid_field", f"data exceeds {MAX_STREAM_DATA} bytes")
    eof = fields["eof"]
    if not isinstance(eof, bool):
        raise FrameError("invalid_field", "eof must be a boolean")
    return scan_stream(data, eof)


def scan_stream(data: bytes, eof: bool) -> dict[str, object]:
    """Scan ``data`` left to right for v1 frames.

    A candidate that cannot be completed is either held in ``remainder``
    (``eof=False``) or reported as ``truncated_frame`` and dropped
    (``eof=True``); every byte that is neither part of a valid frame nor held
    in ``remainder`` is counted in ``discarded``.
    """
    frames: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    discarded = 0
    remainder = b""
    pos = 0
    end = len(data)

    def finish_truncated(offset: int) -> None:
        nonlocal discarded, remainder
        if eof:
            errors.append({"offset": offset, "code": "truncated_frame"})
            discarded += end - offset
        else:
            remainder = data[offset:]

    while True:
        magic = data.find(_MAGIC, pos)
        if magic < 0:
            # A trailing lone 0x50 may be the first half of a split magic.
            if end > pos and data[end - 1] == _MAGIC_FIRST_BYTE:
                discarded += end - 1 - pos
                finish_truncated(end - 1)
            else:
                discarded += end - pos
            break
        discarded += magic - pos
        available = end - magic
        if available < HEADER_LEN:
            finish_truncated(magic)
            break
        _, version, flags, sequence, opcode, length = _HEADER.unpack(data[magic : magic + HEADER_LEN])
        if version != VERSION:
            errors.append({"offset": magic, "code": "unsupported_version"})
            discarded += 1  # the failed candidate's first magic byte
            pos = magic + 1
            continue
        if length > MAX_PAYLOAD:
            errors.append({"offset": magic, "code": "invalid_length"})
            discarded += 1
            pos = magic + 1
            continue
        total = HEADER_LEN + length + CRC_LEN
        if available < total:
            finish_truncated(magic)
            break
        payload_start = magic + HEADER_LEN
        payload_end = payload_start + length
        (crc_expected,) = _UINT32.unpack(data[payload_end : payload_end + CRC_LEN])
        if zlib.crc32(data[magic + 2 : payload_end]) != crc_expected:
            errors.append({"offset": magic, "code": "checksum_mismatch"})
            discarded += 1
            pos = magic + 1
            continue
        frames.append(
            {
                "offset": magic,
                "version": version,
                "flags": flags,
                "sequence": sequence,
                "opcode": opcode,
                "payload": data[payload_start:payload_end].hex(),
            }
        )
        pos = magic + total

    return {
        "frames": frames,
        "errors": errors,
        "discarded": discarded,
        "remainder": remainder.hex(),
    }
