"""Multiplexed channel frame codec on top of the version-1 frame layout.

Three logical channels share one ProbePoint frame stream, each mapping to a
fixed opcode::

    debug  -> 0x0001
    serial -> 0x0002
    log    -> 0x0003

Channel frames always carry ``flags == 0``. Stream parsing reuses the v1
frame scanner from :mod:`probepoint.frames` unchanged -- same validation,
error codes, bad-candidate resynchronization, noise counting and tail
semantics. A CRC-valid frame with nonzero flags reports
``unsupported_flags``; one whose opcode is outside the channel mapping
reports ``unsupported_channel`` (flags take precedence when both fail).
Such a frame produces no event, is counted in ``discarded`` as a whole and
scanning resumes right after it.
"""

from __future__ import annotations

from .frames import (
    CRC_LEN,
    HEADER_LEN,
    MAX_PAYLOAD,
    FrameError,
    decode_stream,
    encode_frame,
)

CHANNEL_OPCODES: dict[str, int] = {
    "debug": 0x0001,
    "serial": 0x0002,
    "log": 0x0003,
}
OPCODE_CHANNELS = {opcode: name for name, opcode in CHANNEL_OPCODES.items()}

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


class ChannelError(Exception):
    """Validation failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint(value: object, bits: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ChannelError("invalid_field", f"{field} must be an unsigned {bits}-bit integer")
    if value < 0 or value >= 1 << bits:
        raise ChannelError("invalid_field", f"{field} out of range for unsigned {bits}-bit integer")
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise ChannelError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise ChannelError("invalid_field", f"{field} must be even-length hex without prefix or separators")
    return bytes.fromhex(value)


def _check_fields(body: object, expected: frozenset[str]) -> dict:
    if not isinstance(body, dict):
        raise ChannelError("invalid_request", "request body must be a JSON object")
    missing = expected - body.keys()
    extra = body.keys() - expected
    if missing:
        raise ChannelError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise ChannelError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def encode_channel(body: object) -> dict[str, str]:
    """Validate a channel encode request and return {"frame": <hex>}."""
    fields = _check_fields(body, frozenset({"channel", "sequence", "data"}))
    channel = fields["channel"]
    if not isinstance(channel, str) or channel not in CHANNEL_OPCODES:
        raise ChannelError("invalid_field", "channel must be one of debug, serial, log")
    sequence = _uint(fields["sequence"], 32, "sequence")
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_PAYLOAD:
        raise ChannelError("invalid_field", f"data exceeds {MAX_PAYLOAD} bytes")

    result = encode_frame(
        {
            "flags": 0,
            "sequence": sequence,
            "opcode": CHANNEL_OPCODES[channel],
            "payload": data.hex(),
        }
    )
    return {"frame": result["frame"]}


def decode_channel_stream(body: object) -> dict[str, object]:
    """Validate a channel decode-stream request and scan one v1 fragment.

    Stateless like :func:`probepoint.frames.decode_stream`: callers
    resubmit the previously returned ``remainder`` concatenated with fresh
    bytes. The v1 scanner supplies frame, error, discarded and remainder
    results; CRC-valid frames are then classified against the channel
    mapping.
    """
    try:
        scanned = decode_stream(body)
    except FrameError as exc:
        raise ChannelError(exc.code, exc.message)

    # Frames and scanner errors are each in ascending offset order and no
    # frame offset coincides with a scanner error offset, so the per-frame
    # classification errors merge in stably by offset.
    rejected: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    rejected_bytes = 0
    for frame in scanned["frames"]:
        if frame["flags"] != 0:
            rejected.append({"offset": frame["offset"], "code": "unsupported_flags"})
        elif frame["opcode"] not in OPCODE_CHANNELS:
            rejected.append({"offset": frame["offset"], "code": "unsupported_channel"})
        else:
            events.append(
                {
                    "offset": frame["offset"],
                    "channel": OPCODE_CHANNELS[frame["opcode"]],
                    "sequence": frame["sequence"],
                    "data": frame["payload"],
                }
            )
            continue
        rejected_bytes += HEADER_LEN + len(frame["payload"]) // 2 + CRC_LEN

    scanner_errors = scanned["errors"]
    errors: list[dict[str, object]] = []
    a = b = 0
    while a < len(scanner_errors) and b < len(rejected):
        if scanner_errors[a]["offset"] <= rejected[b]["offset"]:
            errors.append(scanner_errors[a])
            a += 1
        else:
            errors.append(rejected[b])
            b += 1
    errors.extend(scanner_errors[a:])
    errors.extend(rejected[b:])

    return {
        "events": events,
        "errors": errors,
        "discarded": scanned["discarded"] + rejected_bytes,
        "remainder": scanned["remainder"],
    }
