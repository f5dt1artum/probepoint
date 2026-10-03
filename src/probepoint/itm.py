"""ARM ITM trace packet stream decoder (stateless).

Source packet header byte layout::

    bits 0-1   payload size code: 1 -> 1 byte, 2 -> 2 bytes, 3 -> 4 bytes
    bit  2     source: 0 = software, 1 = hardware
    bits 3-7   port number 0..31

Bytes whose low two bits are zero are protocol packets instead::

    0x00   padding; at least five of them followed by 0x80 form a sync packet
    0x70   overflow packet
    0x80   sync packet terminator (needs five preceding 0x00 bytes)
"""

from __future__ import annotations

MAX_STREAM_DATA = 1 << 20  # 1 MiB per decode-stream request

SYNC_PADDING = 0x00
OVERFLOW = 0x70
SYNC_END = 0x80
SYNC_MIN_ZEROS = 5

_SIZE_BY_CODE = {1: 1, 2: 2, 3: 4}

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


class ItmError(Exception):
    """Validation or codec failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise ItmError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise ItmError("invalid_field", f"{field} must be even-length hex without prefix or separators")
    return bytes.fromhex(value)


def _check_fields(body: object, expected: frozenset[str]) -> dict:
    if not isinstance(body, dict):
        raise ItmError("invalid_request", "request body must be a JSON object")
    missing = expected - body.keys()
    extra = body.keys() - expected
    if missing:
        raise ItmError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise ItmError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def decode_stream(body: object) -> dict[str, object]:
    """Validate a decode-stream request and scan one stateless ITM fragment.

    The fragment carries no session state: callers resubmit the previously
    returned ``remainder`` concatenated with fresh bytes. Events and errors
    are reported in offset order; padding and error-consumed bytes are
    counted as ``discarded`` unless they may still complete with future
    data, in which case they form the ``remainder``.
    """
    fields = _check_fields(body, frozenset({"data", "eof"}))
    if not isinstance(fields["eof"], bool):
        raise ItmError("invalid_field", "eof must be a boolean")
    eof = fields["eof"]
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_STREAM_DATA:
        raise ItmError("invalid_field", f"data exceeds {MAX_STREAM_DATA} decoded bytes")

    events: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    discarded = 0

    n = len(data)
    i = 0
    while i < n:
        byte = data[i]

        if byte == SYNC_PADDING:
            # A zero run is padding unless at least five zeros are closed by
            # 0x80, in which case the last five zeros join the sync packet.
            j = i
            while j < n and data[j] == SYNC_PADDING:
                j += 1
            run = j - i
            if j < n and data[j] == SYNC_END:
                if run >= SYNC_MIN_ZEROS:
                    discarded += run - SYNC_MIN_ZEROS
                    events.append({"offset": j - SYNC_MIN_ZEROS, "type": "sync"})
                else:
                    discarded += run
                    errors.append({"offset": j, "code": "unsupported_packet"})
                    discarded += 1
                i = j + 1
                continue
            if j == n:
                # Trailing zeros may still become a sync packet; keep at
                # most the last five while more data may arrive.
                if eof:
                    discarded += run
                else:
                    keep = min(run, SYNC_MIN_ZEROS)
                    discarded += run - keep
                    i = j - keep
                break
            discarded += run
            i = j
            continue

        if byte == OVERFLOW:
            events.append({"offset": i, "type": "overflow"})
            i += 1
            continue

        if byte == SYNC_END:
            # 0x80 without five preceding zeros is not a valid packet.
            errors.append({"offset": i, "code": "unsupported_packet"})
            discarded += 1
            i += 1
            continue

        size = _SIZE_BY_CODE.get(byte & 0x03)
        if size is None:
            errors.append({"offset": i, "code": "unsupported_packet"})
            discarded += 1
            i += 1
            continue

        if n - i < 1 + size:
            # Incomplete payload: wait for more bytes, or report the
            # truncated candidate at end of stream.
            if eof:
                errors.append({"offset": i, "code": "truncated_packet"})
                discarded += n - i
                i = n
            break

        events.append(
            {
                "offset": i,
                "type": "source",
                "source": "hardware" if byte & 0x04 else "software",
                "port": byte >> 3,
                "size": size,
                "data": data[i + 1 : i + 1 + size].hex(),
            }
        )
        i += 1 + size

    remainder = b"" if eof else data[i:]
    return {
        "events": events,
        "errors": errors,
        "discarded": discarded,
        "remainder": remainder.hex(),
    }
