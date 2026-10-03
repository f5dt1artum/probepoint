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
MAX_MEMORY = 4096  # max bytes read/written by one m/M command
MAX_REGISTER = 32  # max bytes in one p/P register value

READ_MEMORY = "read_memory"
WRITE_MEMORY = "write_memory"
READ_REGISTER = "read_register"
WRITE_REGISTER = "write_register"
CONTINUE = "continue"
SINGLE_STEP = "single_step"
_READ_OPERATIONS = frozenset({READ_MEMORY, READ_REGISTER})
_WRITE_OPERATIONS = frozenset({WRITE_MEMORY, WRITE_REGISTER})
_EXECUTION_OPERATIONS = frozenset({CONTINUE, SINGLE_STEP})
_COMMAND_OPERATIONS = _READ_OPERATIONS | _WRITE_OPERATIONS | _EXECUTION_OPERATIONS

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


def _uint(value: object, bits: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RspError("invalid_field", f"{field} must be an unsigned {bits}-bit integer")
    if value < 0 or value >= 1 << bits:
        raise RspError("invalid_field", f"{field} out of range for unsigned {bits}-bit integer")
    return value


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


_ENCODE_FIELDS = {
    READ_MEMORY: frozenset({"operation", "address", "length"}),
    WRITE_MEMORY: frozenset({"operation", "address", "data"}),
    READ_REGISTER: frozenset({"operation", "register"}),
    WRITE_REGISTER: frozenset({"operation", "register", "value"}),
    CONTINUE: frozenset({"operation"}),
    SINGLE_STEP: frozenset({"operation"}),
}
_ENCODE_OPTIONAL = {
    CONTINUE: frozenset({"address"}),
    SINGLE_STEP: frozenset({"address"}),
}
_RESPONSE_FIELDS = {
    READ_MEMORY: frozenset({"operation", "payload", "expected_length"}),
    READ_REGISTER: frozenset({"operation", "payload", "expected_size"}),
    WRITE_MEMORY: frozenset({"operation", "payload"}),
    WRITE_REGISTER: frozenset({"operation", "payload"}),
    CONTINUE: frozenset({"operation", "payload"}),
    SINGLE_STEP: frozenset({"operation", "payload"}),
}
_ADDRESS_MAX = 0xFFFFFFFF


def _no_overflow(address: int, count: int, field: str) -> None:
    # address + accessed bytes must not cross 0xffffffff (u32 overflow).
    if address + count > _ADDRESS_MAX:
        raise RspError("invalid_field", f"{field} crosses the end of the 32-bit address space")


def _operation_fields(
    body: object,
    allowed_by_operation: dict[str, frozenset[str]],
    optional_by_operation: dict[str, frozenset[str]] | None = None,
) -> tuple[str, dict]:
    if not isinstance(body, dict):
        raise RspError("invalid_request", "request body must be a JSON object")
    if "operation" not in body:
        raise RspError("invalid_field", "missing field(s): operation")
    operation = body["operation"]
    if not isinstance(operation, str) or operation not in allowed_by_operation:
        raise RspError(
            "invalid_field", "operation must be one of: " + ", ".join(sorted(_COMMAND_OPERATIONS))
        )
    allowed = allowed_by_operation[operation]
    optional = (optional_by_operation or {}).get(operation, frozenset())
    missing = allowed - body.keys()
    if missing:
        raise RspError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    extra = body.keys() - allowed - optional
    if extra:
        raise RspError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return operation, body


def encode_command(body: object) -> dict[str, str]:
    """Validate a command request and return its ASCII RSP payload as hex.

    The returned ``{"payload": <lowercase hex>}`` feeds directly into
    :func:`encode_packet`.  The encoded command is ``m``/``M`` for memory,
    ``p``/``P`` for registers and ``c``/``s`` for continue/step; numbers are
    bare lowercase hex and write data keeps its byte order.
    """
    operation, fields = _operation_fields(body, _ENCODE_FIELDS, _ENCODE_OPTIONAL)

    if operation == READ_MEMORY:
        address = _uint(fields["address"], 32, "address")
        length = _uint(fields["length"], 32, "length")
        if not 1 <= length <= MAX_MEMORY:
            raise RspError("invalid_field", f"length must be between 1 and {MAX_MEMORY}")
        _no_overflow(address, length, "address + length")
        command = f"m{address:x},{length:x}".encode("ascii")

    elif operation == WRITE_MEMORY:
        address = _uint(fields["address"], 32, "address")
        data_text = fields["data"]
        data = _hex_bytes(data_text, "data")
        if not 1 <= len(data) <= MAX_MEMORY:
            raise RspError("invalid_field", f"data must be between 1 and {MAX_MEMORY} bytes")
        _no_overflow(address, len(data), "address + data length")
        command = f"M{address:x},{len(data):x}:".encode("ascii") + data_text.lower().encode("ascii")

    elif operation == READ_REGISTER:
        register = _uint(fields["register"], 16, "register")
        command = f"p{register:x}".encode("ascii")

    elif operation == WRITE_REGISTER:
        register = _uint(fields["register"], 16, "register")
        value_text = fields["value"]
        value = _hex_bytes(value_text, "value")
        if not 1 <= len(value) <= MAX_REGISTER:
            raise RspError("invalid_field", f"value must be between 1 and {MAX_REGISTER} bytes")
        command = f"P{register:x}=".encode("ascii") + value_text.lower().encode("ascii")

    else:  # CONTINUE / SINGLE_STEP
        letter = b"c" if operation == CONTINUE else b"s"
        if "address" in fields:
            address = _uint(fields["address"], 32, "address")
            command = letter + f"{address:x}".encode("ascii")
        else:
            command = letter

    return {"payload": command.hex()}


def _two_hex(text: str) -> bool:
    return len(text) == 2 and all(c in "0123456789abcdefABCDEF" for c in text)


def _decode_execution_reply(text: str) -> dict[str, object]:
    """Interpret a continue/step reply per the stop-reply RSP forms."""
    prefix, rest = text[0], text[1:]

    if prefix == "S":
        if not _two_hex(rest):
            raise RspError("invalid_response", "stop response must be S followed by two hex digits")
        return {"status": "stopped", "signal": rest.lower(), "details": []}

    if prefix == "T":
        if not (len(rest) >= 2 and all(c in _HEXDIGITS for c in rest[:2])):
            raise RspError("invalid_response", "stop response must be T followed by two hex digits")
        tail = rest[2:]
        details: list[dict[str, str]] = []
        if tail:
            fields = tail.split(";")
            # A trailing semicolon is allowed; any other empty segment means
            # a field is missing or malformed.
            if fields[-1] == "":
                fields.pop()
            for field in fields:
                key, sep, value = field.partition(":")
                if not sep or not key or not value:
                    raise RspError(
                        "invalid_response", "T fields must be non-empty ASCII key:value pairs"
                    )
                details.append({"key": key, "value": value})
        return {"status": "stopped", "signal": rest[:2].lower(), "details": details}

    if prefix == "W":
        if not _two_hex(rest):
            raise RspError("invalid_response", "exit response must be W followed by two hex digits")
        return {"status": "exited", "code": rest.lower()}

    if prefix == "X":
        if not _two_hex(rest):
            raise RspError(
                "invalid_response", "termination response must be X followed by two hex digits"
            )
        return {"status": "terminated", "signal": rest.lower()}

    if prefix == "O":
        if len(rest) % 2 != 0 or any(c not in _HEXDIGITS for c in rest):
            raise RspError("invalid_response", "console response must be O followed by even-length hex")
        return {"status": "console", "data": rest.lower()}

    raise RspError("invalid_response", f"unknown execution response prefix: {prefix}")


def decode_command_response(body: object) -> dict[str, object]:
    """Validate and interpret a target response payload from decode-stream.

    Returns ``{"status": "unsupported"}`` for an empty payload,
    ``{"status": "error", "code": <two lowercase hex>}`` for an ``E`` reply,
    ``{"status": "ok", "data"|"value": <lowercase hex>}`` for a read and
    ``{"status": "ok"}`` for a write's ``OK``.  Continue/step replies decode
    the stop (``S``/``T``), exit (``W``), termination (``X``) and console
    (``O``) forms.  Anything else is an ``invalid_response`` error.
    """
    operation, fields = _operation_fields(body, _RESPONSE_FIELDS)
    is_read = operation in _READ_OPERATIONS
    is_execution = operation in _EXECUTION_OPERATIONS

    if is_read:
        expect_field = "expected_length" if operation == READ_MEMORY else "expected_size"
        limit = MAX_MEMORY if operation == READ_MEMORY else MAX_REGISTER
        expected = _uint(fields[expect_field], 32, expect_field)
        if not 1 <= expected <= limit:
            raise RspError("invalid_field", f"{expect_field} must be between 1 and {limit}")

    # The outer hex wrapping is a request field; malformed hex is invalid_field.
    payload = _hex_bytes(fields["payload"], "payload")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        raise RspError("invalid_response", "response payload must be ASCII")

    if len(text) == 0:
        return {"status": "unsupported"}

    if text == "OK":
        if is_read:
            raise RspError("invalid_response", "OK is not a valid read response")
        if is_execution:
            raise RspError("invalid_response", "OK is not a valid execution response")
        return {"status": "ok"}

    if text[0] == "E":
        if len(text) != 3 or any(c not in "0123456789abcdefABCDEF" for c in text[1:]):
            raise RspError("invalid_response", "error response must be E followed by two hex digits")
        return {"status": "error", "code": text[1:].lower()}

    if is_execution:
        return _decode_execution_reply(text)

    if not is_read:
        raise RspError("invalid_response", "write response must be OK, empty or an E error")

    if len(text) % 2 != 0 or any(c not in _HEXDIGITS for c in text):
        raise RspError("invalid_response", "read response must be even-length hex data")
    if len(text) // 2 != expected:
        raise RspError("invalid_response", f"response length does not match {expect_field}")

    if operation == READ_MEMORY:
        return {"status": "ok", "data": text.lower()}
    return {"status": "ok", "value": text.lower()}
