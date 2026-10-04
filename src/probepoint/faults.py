"""Offline ARMv7-M Cortex-M fault snapshot diagnosis (v1).

The analyzer works purely on the exception stack frame and fault status
registers supplied in the request: it never connects to a target, reads no
hardware and keeps no state.  The stacked frame is the classic 8-word
ARMv7-M exception frame laid out as little-endian ``u32`` values::

    r0, r1, r2, r3, r12, lr, pc, xpsr

Diagnosis only decodes the documented CFSR/HFSR cause bits; the MMARVALID
and BFARVALID validity bits gate the fault addresses but are never reported
as causes, and undefined bits remain only in the raw ``status`` echo.
"""

from __future__ import annotations

FRAME_SIZE = 32  # eight stacked u32 words
FRAME_WORDS = 8
_UINT32_MAX = (1 << 32) - 1
_THUMB_BIT = 1 << 24
_MMARVALID = 1 << 7
_BFARVALID = 1 << 15

_REQUIRED_FIELDS = frozenset({"stacked_frame", "cfsr", "hfsr", "mmfar", "bfar"})
_FRAME_WORD_NAMES = ("r0", "r1", "r2", "r3", "r12", "lr", "pc", "xpsr")

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

# (bit, name) tables, kept in ascending bit order.
_MEMMANAGE_CAUSES = (
    (0, "IACCVIOL"),
    (1, "DACCVIOL"),
    (3, "MUNSTKERR"),
    (4, "MSTKERR"),
    (5, "MLSPERR"),
)
_BUSFAULT_CAUSES = (
    (8, "IBUSERR"),
    (9, "PRECISERR"),
    (10, "IMPRECISERR"),
    (11, "UNSTKERR"),
    (12, "STKERR"),
    (13, "LSPERR"),
)
_USAGEFAULT_CAUSES = (
    (16, "UNDEFINSTR"),
    (17, "INVSTATE"),
    (18, "INVPC"),
    (19, "NOCP"),
    (24, "UNALIGNED"),
    (25, "DIVBYZERO"),
)
_CFSR_CAUSES = _MEMMANAGE_CAUSES + _BUSFAULT_CAUSES + _USAGEFAULT_CAUSES
_HARDFAULT_CAUSES = (
    (1, "VECTTBL"),
    (30, "FORCED"),
    (31, "DEBUGEVT"),
)


class FaultError(Exception):
    """Validation failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint32(value: object, field: str) -> int:
    # bool is a subclass of int but must never masquerade as a number.
    if not isinstance(value, int) or isinstance(value, bool):
        raise FaultError("invalid_field", f"{field} must be an unsigned 32-bit integer")
    if value < 0 or value > _UINT32_MAX:
        raise FaultError("invalid_field", f"{field} out of range for unsigned 32-bit integer")
    return value


def _stacked_frame(value: object) -> bytes:
    if not isinstance(value, str):
        raise FaultError("invalid_field", "stacked_frame must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise FaultError(
            "invalid_field", "stacked_frame must be even-length hex without prefix or separators"
        )
    raw = bytes.fromhex(value)
    if len(raw) != FRAME_SIZE:
        raise FaultError(
            "invalid_field", f"stacked_frame must decode to exactly {FRAME_SIZE} bytes"
        )
    return raw


def _decode_causes(register: str, value: int, table: tuple) -> list[dict[str, object]]:
    return [
        {"register": register, "bit": bit, "name": name}
        for bit, name in table
        if value & (1 << bit)
    ]


def analyze_cortex_m_fault(body: object) -> dict[str, object]:
    """Validate a Cortex-M fault request and diagnose the snapshot.

    Returns ``{"frame", "status", "primary", "causes", "fault_addresses"}``.
    A frame whose xPSR Thumb bit is clear is still reported (with
    ``frame_valid`` false); no partial results are emitted on validation
    failure — :class:`FaultError` is raised instead.
    """
    if not isinstance(body, dict):
        raise FaultError("invalid_request", "request body must be a JSON object")
    missing = _REQUIRED_FIELDS - body.keys()
    extra = body.keys() - _REQUIRED_FIELDS
    if missing:
        raise FaultError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise FaultError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")

    raw = _stacked_frame(body["stacked_frame"])
    cfsr = _uint32(body["cfsr"], "cfsr")
    hfsr = _uint32(body["hfsr"], "hfsr")
    mmfar = _uint32(body["mmfar"], "mmfar")
    bfar = _uint32(body["bfar"], "bfar")

    words = [int.from_bytes(raw[offset : offset + 4], "little") for offset in range(0, FRAME_SIZE, 4)]
    frame: dict[str, object] = dict(zip(_FRAME_WORD_NAMES, words))
    frame["instruction_address"] = frame["pc"] & ~1
    frame["frame_valid"] = bool(frame["xpsr"] & _THUMB_BIT)

    causes = _decode_causes("cfsr", cfsr, _CFSR_CAUSES)
    causes.extend(_decode_causes("hfsr", hfsr, _HARDFAULT_CAUSES))

    memmanage = _decode_causes("cfsr", cfsr, _MEMMANAGE_CAUSES)
    busfault = _decode_causes("cfsr", cfsr, _BUSFAULT_CAUSES)
    usagefault = _decode_causes("cfsr", cfsr, _USAGEFAULT_CAUSES)
    hardfault = _decode_causes("hfsr", hfsr, _HARDFAULT_CAUSES)
    for label, present in (
        ("memmanage", memmanage),
        ("busfault", busfault),
        ("usagefault", usagefault),
        ("hardfault", hardfault),
    ):
        if present:
            primary = label
            break
    else:
        primary = "none"

    fault_addresses = {
        "mmfar": mmfar if cfsr & _MMARVALID else None,
        "bfar": bfar if cfsr & _BFARVALID else None,
    }

    return {
        "frame": frame,
        "status": {"cfsr": cfsr, "hfsr": hfsr},
        "primary": primary,
        "causes": causes,
        "fault_addresses": fault_addresses,
    }
