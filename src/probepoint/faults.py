"""Offline Cortex-M fault snapshot diagnosis (ARMv7-M, v1).

The analyzer works purely on the exception stack frame and fault status
registers supplied in the request: it never connects to a target, reads no
hardware and keeps no state.  The stacked frame is the standard ARMv7-M
8-word exception frame, 32 little-endian bytes holding in order
``r0, r1, r2, r3, r12, lr, pc, xpsr``.

Only the documented CFSR/HFSR cause bits are decoded; set-but-undefined
bits are preserved verbatim in ``status`` and never appear in ``causes``.
The MMARVALID/BFARVALID valid bits only gate the reported fault addresses
and are themselves never causes.
"""

from __future__ import annotations

_UINT32_MAX = (1 << 32) - 1
_FRAME_LEN = 32  # eight stacked words
_THUMB_BIT = 1 << 24  # xpsr T bit

_REQUIRED_FIELDS = frozenset({"stacked_frame", "cfsr", "hfsr", "mmfar", "bfar"})

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

# (bit, name) in ascending bit order per register.
_CFSR_CAUSES: tuple[tuple[int, str], ...] = (
    (0, "IACCVIOL"),
    (1, "DACCVIOL"),
    (3, "MUNSTKERR"),
    (4, "MSTKERR"),
    (5, "MLSPERR"),
    (8, "IBUSERR"),
    (9, "PRECISERR"),
    (10, "IMPRECISERR"),
    (11, "UNSTKERR"),
    (12, "STKERR"),
    (13, "LSPERR"),
    (16, "UNDEFINSTR"),
    (17, "INVSTATE"),
    (18, "INVPC"),
    (19, "NOCP"),
    (24, "UNALIGNED"),
    (25, "DIVBYZERO"),
)
_HFSR_CAUSES: tuple[tuple[int, str], ...] = (
    (30, "FORCED"),
    (31, "DEBUGEVT"),
)

_MMARVALID = 1 << 7
_BFARVALID = 1 << 15

_FRAME_REGISTERS = ("r0", "r1", "r2", "r3", "r12", "lr", "pc", "xpsr")


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
    if len(raw) != _FRAME_LEN:
        raise FaultError(
            "invalid_field", f"stacked_frame must decode to exactly {_FRAME_LEN} bytes"
        )
    return raw


def _decode_causes(register: str, value: int, table: tuple[tuple[int, str], ...]) -> list[dict[str, object]]:
    return [
        {"register": register, "bit": bit, "name": name}
        for bit, name in table
        if value & (1 << bit)
    ]


def _primary(cfsr_causes: list[dict[str, object]], has_hfsr_cause: bool) -> str:
    for category, upper in (("memmanage", 8), ("busfault", 16), ("usagefault", 32)):
        if any(cause["bit"] < upper for cause in cfsr_causes):
            return category
    return "hardfault" if has_hfsr_cause else "none"


def analyze_cortex_m_fault(body: object) -> dict[str, object]:
    """Validate a Cortex-M fault request and diagnose the snapshot.

    Returns ``{"frame", "status", "primary", "causes", "fault_addresses"}``.
    No partial results are emitted: any validation failure raises
    :class:`FaultError`.
    """
    if not isinstance(body, dict):
        raise FaultError("invalid_request", "request body must be a JSON object")
    missing = _REQUIRED_FIELDS - body.keys()
    extra = body.keys() - _REQUIRED_FIELDS
    if missing:
        raise FaultError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise FaultError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")

    raw_frame = _stacked_frame(body["stacked_frame"])
    cfsr = _uint32(body["cfsr"], "cfsr")
    hfsr = _uint32(body["hfsr"], "hfsr")
    mmfar = _uint32(body["mmfar"], "mmfar")
    bfar = _uint32(body["bfar"], "bfar")

    words = [
        int.from_bytes(raw_frame[offset : offset + 4], "little")
        for offset in range(0, _FRAME_LEN, 4)
    ]
    registers = dict(zip(_FRAME_REGISTERS, words))
    pc = registers["pc"]
    xpsr = registers["xpsr"]
    frame = {
        **registers,
        "instruction_address": pc & ~1,
        "frame_valid": bool(xpsr & _THUMB_BIT),
    }

    cfsr_causes = _decode_causes("cfsr", cfsr, _CFSR_CAUSES)
    hfsr_causes = _decode_causes("hfsr", hfsr, _HFSR_CAUSES)

    return {
        "frame": frame,
        "status": {"cfsr": cfsr, "hfsr": hfsr},
        "primary": _primary(cfsr_causes, bool(hfsr_causes)),
        "causes": cfsr_causes + hfsr_causes,
        "fault_addresses": {
            "mmfar": mmfar if cfsr & _MMARVALID else None,
            "bfar": bfar if cfsr & _BFARVALID else None,
        },
    }
