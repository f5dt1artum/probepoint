"""GDB RSP memory/register command payloads and reply decoding.

These helpers sit on top of the packet codec in :mod:`probepoint.rsp`:
``encode_command`` renders the ASCII payload of the ``m``, ``M``, ``p``
and ``P`` commands ready to hand to ``/v1/rsp/encode``, and
``decode_response`` interprets a reply payload recovered by
``/v1/rsp/decode-stream``.  No target connection or session state is
involved; numeric fields render as lowercase hex without leading zeros
and data bytes keep their order.
"""

from __future__ import annotations

from .rsp import _HEXDIGITS, RspError, _check_fields, _hex_bytes

OPERATIONS = frozenset({"read_memory", "write_memory", "read_register", "write_register"})

MAX_ADDRESS = 0xFFFFFFFF  # u32
MAX_REGISTER = 0xFFFF  # u16
MAX_MEM_ACCESS = 4096  # bytes per read_memory/write_memory request
MAX_REG_SIZE = 32  # bytes per register value


def _operation(body: object) -> str:
    if not isinstance(body, dict):
        raise RspError("invalid_request", "request body must be a JSON object")
    op = body.get("operation")
    if not isinstance(op, str) or op not in OPERATIONS:
        raise RspError("invalid_field", f"operation must be one of: {', '.join(sorted(OPERATIONS))}")
    return op


def _int_field(value: object, field: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RspError("invalid_field", f"{field} must be an integer")
    if not lo <= value <= hi:
        raise RspError("invalid_field", f"{field} must be between {lo} and {hi}")
    return value


def _check_span(address: int, count: int) -> None:
    if address + count > MAX_ADDRESS + 1:
        raise RspError("invalid_field", "address plus access size overflows u32")


def encode_command(body: object) -> dict[str, str]:
    """Validate a command request and return {"payload": <lowercase hex>}."""
    op = _operation(body)
    if op == "read_memory":
        fields = _check_fields(body, frozenset({"operation", "address", "length"}))
        address = _int_field(fields["address"], "address", 0, MAX_ADDRESS)
        length = _int_field(fields["length"], "length", 1, MAX_MEM_ACCESS)
        _check_span(address, length)
        text = f"m{address:x},{length:x}"
    elif op == "write_memory":
        fields = _check_fields(body, frozenset({"operation", "address", "data"}))
        address = _int_field(fields["address"], "address", 0, MAX_ADDRESS)
        data = _hex_bytes(fields["data"], "data")
        if not 1 <= len(data) <= MAX_MEM_ACCESS:
            raise RspError("invalid_field", f"data must be 1 to {MAX_MEM_ACCESS} bytes")
        _check_span(address, len(data))
        text = f"M{address:x},{len(data):x}:{data.hex()}"
    elif op == "read_register":
        fields = _check_fields(body, frozenset({"operation", "register"}))
        register = _int_field(fields["register"], "register", 0, MAX_REGISTER)
        text = f"p{register:x}"
    else:  # write_register
        fields = _check_fields(body, frozenset({"operation", "register", "value"}))
        register = _int_field(fields["register"], "register", 0, MAX_REGISTER)
        value = _hex_bytes(fields["value"], "value")
        if not 1 <= len(value) <= MAX_REG_SIZE:
            raise RspError("invalid_field", f"value must be 1 to {MAX_REG_SIZE} bytes")
        text = f"P{register:x}={value.hex()}"
    return {"payload": text.encode("ascii").hex()}


def decode_response(body: object) -> dict[str, str]:
    """Interpret a reply payload for one of the memory/register commands."""
    op = _operation(body)
    expected: int | None = None
    if op == "read_memory":
        fields = _check_fields(body, frozenset({"operation", "payload", "expected_length"}))
        expected = _int_field(fields["expected_length"], "expected_length", 1, MAX_MEM_ACCESS)
    elif op == "read_register":
        fields = _check_fields(body, frozenset({"operation", "payload", "expected_size"}))
        expected = _int_field(fields["expected_size"], "expected_size", 1, MAX_REG_SIZE)
    else:
        fields = _check_fields(body, frozenset({"operation", "payload"}))
    payload = _hex_bytes(fields["payload"], "payload")

    if not payload:
        return {"status": "unsupported"}
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        raise RspError("invalid_response", "reply payload is not ASCII")
    if text.startswith("E"):
        if len(text) != 3 or any(c not in _HEXDIGITS for c in text[1:]):
            raise RspError("invalid_response", "error reply must be E followed by two hex digits")
        return {"status": "error", "code": text[1:].lower()}
    if op in ("write_memory", "write_register"):
        if text != "OK":
            raise RspError("invalid_response", "write reply must be the ASCII string OK")
        return {"status": "ok"}
    assert expected is not None
    if len(text) != expected * 2 or any(c not in _HEXDIGITS for c in text):
        raise RspError("invalid_response", "read reply must be hex data of the expected length")
    key = "data" if op == "read_memory" else "value"
    return {"status": "ok", key: text.lower()}
