"""GDB Remote Serial Protocol (RSP) packet codec.

Packet layout on the wire::

    0x24 ('$')  on-wire payload  0x23 ('#')  checksum (two hex chars)

The payload bytes 0x24, 0x23, 0x7d and 0x2a are escaped as 0x7d ('}')
followed by the original byte XOR 0x20.  The checksum is the sum of the
on-wire (already escaped) payload bytes modulo 256, rendered as two
lowercase hex characters.
"""

from __future__ import annotations

MAX_PAYLOAD = 4096
MAX_STREAM_DATA = 1 << 20  # 1 MiB per decode-stream request

DOLLAR = 0x24  # '$' packet start
HASH = 0x23  # '#' payload/checksum separator
ESCAPE = 0x7D  # '}' escape introducer
STAR = 0x2A  # '*'
ACK = 0x2B  # '+'
NACK = 0x2D  # '-'

_ESCAPED = frozenset({DOLLAR, HASH, ESCAPE, STAR})
_HEX_VALUES = {c: int(chr(c), 16) for c in b"0123456789abcdefABCDEF"}
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


class RspError(Exception):
    """Validation or codec failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise RspError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise RspError("invalid_field", f"{field} must be even-length hex without prefix or separators")
    return bytes.fromhex(value)


def _check_fields(body: object, expected: frozenset[str]) -> dict:
    if not isinstance(body, dict):
        raise RspError("invalid_request", "request body must be a JSON object")
    missing = expected - body.keys()
    extra = body.keys() - expected
    if missing:
        raise RspError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise RspError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def encode_packet(body: object) -> dict[str, str]:
    """Validate an encode request and return {"packet": <lowercase hex>}."""
    fields = _check_fields(body, frozenset({"payload"}))
    payload = _hex_bytes(fields["payload"], "payload")
    if len(payload) > MAX_PAYLOAD:
        raise RspError("invalid_field", f"payload exceeds {MAX_PAYLOAD} bytes")

    wire = bytearray()
    for byte in payload:
        if byte in _ESCAPED:
            wire.append(ESCAPE)
            wire.append(byte ^ 0x20)
        else:
            wire.append(byte)
    checksum = f"{sum(wire) % 256:02x}".encode("ascii")
    packet = bytes([DOLLAR]) + bytes(wire) + bytes([HASH]) + checksum
    return {"packet": packet.hex()}


def decode_stream(body: object) -> dict[str, object]:
    """Validate a decode-stream request and scan one stateless byte fragment.

    The fragment carries no session state: callers resubmit the previously
    returned ``remainder`` concatenated with fresh bytes.  Packets, control
    characters and errors are reported as they appear; bytes that start no
    packet are counted as ``discarded`` unless they may still complete with
    future data, in which case they form the ``remainder``.
    """
    fields = _check_fields(body, frozenset({"data", "eof"}))
    if not isinstance(fields["eof"], bool):
        raise RspError("invalid_field", "eof must be a boolean")
    eof: bool = fields["eof"]
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_STREAM_DATA:
        raise RspError("invalid_field", f"data exceeds {MAX_STREAM_DATA} decoded bytes")

    packets: list[dict[str, object]] = []
    controls: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    discarded = 0

    n = len(data)
    i = 0
    while i < n:
        byte = data[i]
        if byte == ACK:
            controls.append({"offset": i, "type": "ack"})
            i += 1
            continue
        if byte == NACK:
            controls.append({"offset": i, "type": "nack"})
            i += 1
            continue
        if byte != DOLLAR:
            discarded += 1
            i += 1
            continue

        # Parse one packet candidate starting at offset i.
        offset = i
        payload = bytearray()
        wire_sum = 0
        j = i + 1
        # outcome: ("packet", end) | ("nested", start) | ("error", code, end)
        # | ("incomplete",)
        outcome: tuple = ("incomplete",)
        while j < n:
            byte = data[j]
            if byte == DOLLAR:
                # Unescaped '$' restarts the packet; the old candidate fails.
                outcome = ("nested", j)
                break
            if byte == HASH:
                if j + 3 > n:
                    # Fewer than two checksum characters available.
                    outcome = ("incomplete",)
                    break
                hi = _HEX_VALUES.get(data[j + 1])
                lo = _HEX_VALUES.get(data[j + 2])
                if hi is None or lo is None:
                    outcome = ("error", "invalid_checksum", j + 3)
                    break
                if hi * 16 + lo != wire_sum % 256:
                    outcome = ("error", "checksum_mismatch", j + 3)
                    break
                outcome = ("packet", j + 3)
                break
            if byte == ESCAPE:
                if j + 1 >= n:
                    # Trailing lone escape introducer.
                    outcome = ("incomplete",)
                    break
                payload.append(data[j + 1] ^ 0x20)
                wire_sum += ESCAPE + data[j + 1]
                j += 2
            else:
                payload.append(byte)
                wire_sum += byte
                j += 1
            if len(payload) > MAX_PAYLOAD:
                # The unescaped payload can never fit now; fail the
                # candidate at the byte that overflowed the limit.
                outcome = ("error", "invalid_length", j)
                break

        if outcome[0] == "packet":
            packets.append({"offset": offset, "payload": payload.hex()})
            i = outcome[1]
        elif outcome[0] == "nested":
            errors.append({"offset": offset, "code": "nested_start"})
            discarded += outcome[1] - offset
            i = outcome[1]
        elif outcome[0] == "error":
            errors.append({"offset": offset, "code": outcome[1]})
            discarded += outcome[2] - offset
            i = outcome[2]
        elif eof:
            errors.append({"offset": offset, "code": "truncated_packet"})
            discarded += n - offset
            i = n
        else:
            # Candidate might complete once more bytes arrive.
            break

    remainder = b"" if eof else data[i:]
    return {
        "packets": packets,
        "controls": controls,
        "errors": errors,
        "discarded": discarded,
        "remainder": remainder.hex(),
    }
