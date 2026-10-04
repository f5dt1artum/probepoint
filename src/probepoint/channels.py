"""Channel multiplexing over the v1 frame stream.

Debug, serial and log traffic share the ProbePoint v1 frame layout (see
:mod:`probepoint.frames`); the channel is carried in the opcode field::

    debug   0x0001
    serial  0x0002
    log     0x0003

Multiplexed frames always carry zero flags. This module only encodes and
decodes offline; it never connects to a target and keeps no session state.
"""

from __future__ import annotations

import zlib

from .frames import (
    MAGIC,
    MAX_PAYLOAD,
    MAX_STREAM_DATA,
    VERSION,
    FrameError,
    _check_fields,
    _hex_bytes,
    _scan_stream,
    _uint,
    _HEADER,
    _UINT32,
)

CHANNEL_OPCODES = {"debug": 0x0001, "serial": 0x0002, "log": 0x0003}
OPCODE_CHANNELS = {opcode: name for name, opcode in CHANNEL_OPCODES.items()}


def encode_channel(body: object) -> dict[str, str]:
    """Validate a channel encode request and return {"frame": <lowercase hex>}."""
    fields = _check_fields(body, frozenset({"channel", "sequence", "data"}))
    channel = fields["channel"]
    if not isinstance(channel, str) or channel not in CHANNEL_OPCODES:
        raise FrameError("invalid_field", "channel must be one of: debug, serial, log")
    sequence = _uint(fields["sequence"], 32, "sequence")
    payload = _hex_bytes(fields["data"], "data")
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("invalid_field", f"data exceeds {MAX_PAYLOAD} bytes")

    header = _HEADER.pack(MAGIC, VERSION, 0, sequence, CHANNEL_OPCODES[channel], len(payload))
    crc = zlib.crc32(header[2:] + payload)
    frame = header + payload + _UINT32.pack(crc)
    return {"frame": frame.hex()}


def decode_channel_stream(body: object) -> dict[str, object]:
    """Validate a decode-stream request and demultiplex one stateless fragment.

    Scanning, validation, resynchronization, noise counting and tail
    semantics are exactly those of the v1 frame stream. A checksum-valid
    frame with nonzero flags is reported as ``unsupported_flags``; one with
    zero flags but an opcode outside the channel mapping is reported as
    ``unsupported_channel`` (both together yield only ``unsupported_flags``).
    Such frames produce no event, count fully toward ``discarded`` and
    scanning resumes after the frame.
    """
    fields = _check_fields(body, frozenset({"data", "eof"}))
    if not isinstance(fields["eof"], bool):
        raise FrameError("invalid_field", "eof must be a boolean")
    data = _hex_bytes(fields["data"], "data")
    if len(data) > MAX_STREAM_DATA:
        raise FrameError("invalid_field", f"data exceeds {MAX_STREAM_DATA} decoded bytes")

    frames, errors, discarded, remainder = _scan_stream(data, fields["eof"])

    events: list[dict[str, object]] = []
    for frame in frames:
        flags = frame["flags"]
        opcode = frame["opcode"]
        if flags != 0:
            errors.append({"offset": frame["offset"], "code": "unsupported_flags"})
            discarded += frame["total"]
            continue
        channel = OPCODE_CHANNELS.get(opcode)
        if channel is None:
            errors.append({"offset": frame["offset"], "code": "unsupported_channel"})
            discarded += frame["total"]
            continue
        events.append(
            {
                "offset": frame["offset"],
                "channel": channel,
                "sequence": frame["sequence"],
                "data": frame["payload"].hex(),
            }
        )

    # Scanner errors and converted frame errors each arrive in offset order
    # and never share an offset, so a stable sort merges them.
    errors.sort(key=lambda error: error["offset"])
    return {
        "events": events,
        "errors": errors,
        "discarded": discarded,
        "remainder": remainder.hex(),
    }
