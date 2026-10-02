"""GDB Remote Serial Protocol (RSP) packet codec.

Packet layout on the wire::

    0x24 ('$')  packet start
    payload     escaped on-wire payload
    0x23 ('#')  payload terminator
    checksum    2 lowercase hex chars: sum of on-wire payload bytes mod 256

Escaping: payload bytes 0x24, 0x23, 0x7d and 0x2a are sent as 0x7d
followed by the original byte XOR 0x20. Outside a packet candidate,
0x2b ('+') and 0x2d ('-') are ack/nack control bytes.
"""

from __future__ import annotations

from .frames import FrameError

START = 0x24  # '$'
END = 0x23  # '#'
ESCAPE = 0x7D  # '}'
XOR_MASK = 0x20
ACK = 0x2B  # '+'
NACK = 0x2D  # '-'

ESCAPED_BYTES = frozenset({START, END, ESCAPE, 0x2A})

MAX_PAYLOAD = 4096
MAX_STREAM_DATA = 1 << 20  # 1 MiB per decode-stream request

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")
_HEX_VALUE = {ord(c): i for i, c in enumerate("0123456789abcdef")}
_HEX_VALUE.update({ord(c): i for i, c in enumerate("0123456789ABCDEF")})


class RspError(FrameError):
    """Validation or codec failure on the RSP surface."""


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
        if byte in ESCAPED_BYTES:
            wire.append(ESCAPE)
            wire.append(byte ^ XOR_MASK)
        else:
            wire.append(byte)
    checksum = sum(wire) % 256
    packet = bytes([START]) + bytes(wire) + bytes([END]) + f"{checksum:02x}".encode("ascii")
    return {"packet": packet.hex()}


def decode_stream(body: object) -> dict[str, object]:
    """Validate a decode-stream request and scan one stateless byte fragment.

    The fragment carries no session state: callers resubmit the previously
    returned ``remainder`` concatenated with fresh bytes. Packets, control
    bytes and errors are reported as they appear; bytes that belong to no
    packet or control are counted as ``discarded`` unless they may still
    complete with future data, in which case they form the ``remainder``.
    """
    fields = _check_fields(body, frozenset({"data", "eof"}))
    eof = fields["eof"]
    if not isinstance(eof, bool):
        raise RspError("invalid_field", "eof must be a boolean")
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_STREAM_DATA:
        raise RspError("invalid_field", f"data exceeds {MAX_STREAM_DATA} decoded bytes")

    packets: list[dict[str, object]] = []
    controls: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    discarded = 0
    remainder = b""

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
        if byte != START:
            discarded += 1
            i += 1
            continue

        # Scan a packet candidate starting at the 0x24.
        start = i
        j = i + 1
        payload = bytearray()  # unescaped payload bytes
        wire_sum = 0  # sum of on-wire payload bytes
        # ("packet", end) | ("error", code, end) | ("restart", new_start)
        # | ("incomplete",)
        outcome: tuple = ("incomplete",)
        while j < n:
            byte = data[j]
            if byte == START:
                outcome = ("restart", j)
                break
            if byte == END:
                if j + 2 >= n:
                    # Fewer than two checksum characters available.
                    outcome = ("incomplete",)
                    break
                c1, c2 = data[j + 1], data[j + 2]
                if c1 not in _HEX_VALUE or c2 not in _HEX_VALUE:
                    bad = j + 1 if c1 not in _HEX_VALUE else j + 2
                    outcome = ("error", "invalid_checksum", bad + 1)
                    break
                expected = _HEX_VALUE[c1] * 16 + _HEX_VALUE[c2]
                if expected != wire_sum % 256:
                    outcome = ("error", "checksum_mismatch", j + 3)
                    break
                outcome = ("packet", j + 3)
                break
            if byte == ESCAPE:
                if j + 1 >= n:
                    # Trailing lone escape byte.
                    outcome = ("incomplete",)
                    break
                wire_sum += byte + data[j + 1]
                payload.append(data[j + 1] ^ XOR_MASK)
                j += 2
            else:
                wire_sum += byte
                payload.append(byte)
                j += 1
            if len(payload) > MAX_PAYLOAD:
                outcome = ("error", "invalid_length", j)
                break

        kind = outcome[0]
        if kind == "packet":
            packets.append({"offset": start, "payload": payload.hex()})
            i = outcome[1]
        elif kind == "error":
            errors.append({"offset": start, "code": outcome[1]})
            discarded += outcome[2] - start
            i = outcome[2]
        elif kind == "restart":
            errors.append({"offset": start, "code": "nested_start"})
            discarded += outcome[1] - start
            i = outcome[1]
        else:  # incomplete
            if eof:
                errors.append({"offset": start, "code": "truncated_packet"})
                discarded += n - start
            else:
                remainder = data[start:]
            i = n

    return {
        "packets": packets,
        "controls": controls,
        "errors": errors,
        "discarded": discarded,
        "remainder": remainder.hex(),
    }
