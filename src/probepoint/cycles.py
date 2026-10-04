"""Stateless Cortex-M DWT CYCCNT cycle-count analysis (v1).

The analyzer works purely on cycle-counter snapshots supplied in the
request: it never connects to a target, reads no hardware and keeps no
sampled data between calls.  A 32-bit CYCCNT measurement spans at most
one counter wrap, so when ``end < start`` the elapsed count is
``2**32 - start + end`` and the sample is marked as wrapped.
"""

from __future__ import annotations

_UINT32_MAX = (1 << 32) - 1
_MOD32 = 1 << 32
_NANOS_PER_SECOND = 1_000_000_000
_MIN_CLOCK_HZ = 1
_MAX_CLOCK_HZ = _UINT32_MAX
_MIN_SAMPLES = 1
_MAX_SAMPLES = 4096
_MAX_LABEL_LENGTH = 64

_REQUIRED_FIELDS = frozenset({"clock_hz", "samples"})
_SAMPLE_FIELDS = frozenset({"label", "start", "end"})


class CyclesError(Exception):
    """Validation failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint32(value: object, field: str) -> int:
    # bool is a subclass of int but must never masquerade as one.
    if not isinstance(value, int) or isinstance(value, bool):
        raise CyclesError("invalid_field", f"{field} must be an unsigned 32-bit integer")
    if value < 0 or value > _UINT32_MAX:
        raise CyclesError("invalid_field", f"{field} out of range for unsigned 32-bit integer")
    return value


def _check_fields(body: object) -> dict:
    if not isinstance(body, dict):
        raise CyclesError("invalid_request", "request body must be a JSON object")
    missing = _REQUIRED_FIELDS - body.keys()
    extra = body.keys() - _REQUIRED_FIELDS
    if missing:
        raise CyclesError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise CyclesError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def _parse_sample(entry: object, index: int) -> tuple[str, int, int]:
    where = f"samples[{index}]"
    if not isinstance(entry, dict):
        raise CyclesError("invalid_field", f"{where} must be a JSON object")
    missing = _SAMPLE_FIELDS - entry.keys()
    extra = entry.keys() - _SAMPLE_FIELDS
    if missing:
        raise CyclesError(
            "invalid_field", f"{where} missing field(s): {', '.join(sorted(missing))}"
        )
    if extra:
        raise CyclesError(
            "invalid_field", f"{where} has unexpected field(s): {', '.join(sorted(extra))}"
        )
    label = entry["label"]
    if not isinstance(label, str):
        raise CyclesError("invalid_field", f"{where} label must be a string")
    label = label.strip()
    if not label:
        raise CyclesError(
            "invalid_field", f"{where} label must not be empty after trimming whitespace"
        )
    if len(label) > _MAX_LABEL_LENGTH:
        raise CyclesError("invalid_field", f"{where} label must be at most 64 characters")
    start = _uint32(entry["start"], f"{where} start")
    end = _uint32(entry["end"], f"{where} end")
    return label, start, end


def analyze_cycles(body: object) -> dict[str, object]:
    """Validate a CYCCNT analysis request and compute elapsed durations.

    Returns ``{"samples": [...], "summary": [...]}``.  Per-sample output
    keeps input order (including duplicate labels); the summary keeps
    first-occurrence order of the normalized labels.  All arithmetic is
    integral, so every JSON number serializes as an integer.
    """
    fields = _check_fields(body)

    clock_hz = fields["clock_hz"]
    if not isinstance(clock_hz, int) or isinstance(clock_hz, bool):
        raise CyclesError("invalid_field", "clock_hz must be an integer")
    if not _MIN_CLOCK_HZ <= clock_hz <= _MAX_CLOCK_HZ:
        raise CyclesError(
            "invalid_field",
            f"clock_hz must be between {_MIN_CLOCK_HZ} and {_MAX_CLOCK_HZ}",
        )

    raw_samples = fields["samples"]
    if not isinstance(raw_samples, list):
        raise CyclesError("invalid_field", "samples must be an array")
    if not _MIN_SAMPLES <= len(raw_samples) <= _MAX_SAMPLES:
        raise CyclesError(
            "invalid_field", f"samples must contain between {_MIN_SAMPLES} and {_MAX_SAMPLES} items"
        )

    # Validate every sample before producing any output, so a bad request
    # never returns partial results.
    parsed = [_parse_sample(entry, index) for index, entry in enumerate(raw_samples)]

    samples: list[dict[str, object]] = []
    totals: dict[str, dict[str, int]] = {}
    order: list[str] = []
    for label, start, end in parsed:
        if end >= start:
            cycles = end - start
            wrapped = False
        else:
            # At most one wrap of the 32-bit free-running counter.
            cycles = _MOD32 - start + end
            wrapped = True
        duration_ns = cycles * _NANOS_PER_SECOND // clock_hz
        samples.append(
            {
                "label": label,
                "start": start,
                "end": end,
                "cycles": cycles,
                "wrapped": wrapped,
                "duration_ns": duration_ns,
            }
        )
        if label not in totals:
            totals[label] = {
                "count": 0,
                "total_cycles": 0,
                "min_cycles": cycles,
                "max_cycles": cycles,
                "total_duration_ns": 0,
            }
            order.append(label)
        aggregate = totals[label]
        aggregate["count"] += 1
        aggregate["total_cycles"] += cycles
        aggregate["min_cycles"] = min(aggregate["min_cycles"], cycles)
        aggregate["max_cycles"] = max(aggregate["max_cycles"], cycles)
        aggregate["total_duration_ns"] += duration_ns

    summary: list[dict[str, object]] = []
    for label in order:
        aggregate = totals[label]
        count = aggregate["count"]
        summary.append(
            {
                "label": label,
                "count": count,
                "total_cycles": aggregate["total_cycles"],
                "min_cycles": aggregate["min_cycles"],
                "max_cycles": aggregate["max_cycles"],
                "average_cycles": aggregate["total_cycles"] // count,
                "total_duration_ns": aggregate["total_duration_ns"],
                "average_duration_ns": aggregate["total_duration_ns"] // count,
            }
        )

    return {"samples": samples, "summary": summary}
