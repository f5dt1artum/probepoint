"""Stateless Cortex-M DWT cycle-count analysis (v1).

The analyzer works purely on CYCCNT start/end snapshots supplied in the
request: it never connects to a target, reads no hardware and keeps no
sampling state.  A measurement may cross at most one 32-bit counter
wrap: when ``end < start`` the elapsed count is ``2^32 - start + end``.
All time conversion is integer arithmetic; JSON numbers emitted here are
always integers, never floats or scientific notation.
"""

from __future__ import annotations

_NANOS_PER_SECOND = 1_000_000_000
_UINT32_MOD = 1 << 32
_UINT32_MAX = _UINT32_MOD - 1
_MAX_SAMPLES = 4096
_MAX_LABEL_LENGTH = 64

_CLOCK_FIELDS = frozenset({"clock_hz", "samples"})
_SAMPLE_FIELDS = frozenset({"label", "start", "end"})


class PerformanceError(Exception):
    """Validation failure carrying the public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _uint32(value: object, field: str) -> int:
    # bool is a subclass of int but must never masquerade as a number.
    if not isinstance(value, int) or isinstance(value, bool):
        raise PerformanceError("invalid_field", f"{field} must be an unsigned 32-bit integer")
    if value < 0 or value > _UINT32_MAX:
        raise PerformanceError("invalid_field", f"{field} out of range for unsigned 32-bit integer")
    return value


def _parse_sample(entry: object, index: int) -> tuple[str, int, int]:
    where = f"samples[{index}]"
    if not isinstance(entry, dict):
        raise PerformanceError("invalid_field", f"{where} must be a JSON object")
    missing = _SAMPLE_FIELDS - entry.keys()
    extra = entry.keys() - _SAMPLE_FIELDS
    if missing:
        raise PerformanceError(
            "invalid_field", f"{where} missing field(s): {', '.join(sorted(missing))}"
        )
    if extra:
        raise PerformanceError(
            "invalid_field", f"{where} has unexpected field(s): {', '.join(sorted(extra))}"
        )
    label = entry["label"]
    if not isinstance(label, str):
        raise PerformanceError("invalid_field", f"{where}.label must be a string")
    label = label.strip()
    if not label:
        raise PerformanceError(
            "invalid_field", f"{where}.label must not be empty after trimming whitespace"
        )
    if len(label) > _MAX_LABEL_LENGTH:
        raise PerformanceError(
            "invalid_field", f"{where}.label must be at most {_MAX_LABEL_LENGTH} characters"
        )
    start = _uint32(entry["start"], f"{where}.start")
    end = _uint32(entry["end"], f"{where}.end")
    return label, start, end


def analyze_cycles(body: object) -> dict[str, object]:
    """Validate a cycle-analysis request and compute timings.

    Returns ``{"samples": [...], "summary": [...]}`` with samples kept in
    input order (duplicates preserved) and summary aggregates ordered by
    first appearance of each normalized label.  No partial results are
    emitted: any validation failure raises :class:`PerformanceError`.
    """
    if not isinstance(body, dict):
        raise PerformanceError("invalid_request", "request body must be a JSON object")
    missing = _CLOCK_FIELDS - body.keys()
    extra = body.keys() - _CLOCK_FIELDS
    if missing:
        raise PerformanceError(
            "invalid_field", f"missing field(s): {', '.join(sorted(missing))}"
        )
    if extra:
        raise PerformanceError(
            "invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}"
        )

    clock_hz = body["clock_hz"]
    if not isinstance(clock_hz, int) or isinstance(clock_hz, bool):
        raise PerformanceError("invalid_field", "clock_hz must be an integer")
    if not 1 <= clock_hz <= _UINT32_MAX:
        raise PerformanceError(
            "invalid_field", f"clock_hz must be between 1 and {_UINT32_MAX}"
        )

    raw_samples = body["samples"]
    if not isinstance(raw_samples, list):
        raise PerformanceError("invalid_field", "samples must be an array")
    if not 1 <= len(raw_samples) <= _MAX_SAMPLES:
        raise PerformanceError(
            "invalid_field", f"samples must contain between 1 and {_MAX_SAMPLES} entries"
        )

    results: list[dict[str, object]] = []
    order: list[str] = []
    totals: dict[str, dict[str, int]] = {}

    for index, entry in enumerate(raw_samples):
        label, start, end = _parse_sample(entry, index)
        if end >= start:
            cycles = end - start
            wrapped = False
        else:
            # Exactly one wrap of the 32-bit CYCCNT counter.
            cycles = _UINT32_MOD - start + end
            wrapped = True
        duration_ns = (cycles * _NANOS_PER_SECOND) // clock_hz

        results.append(
            {
                "label": label,
                "start": start,
                "end": end,
                "cycles": cycles,
                "wrapped": wrapped,
                "duration_ns": duration_ns,
            }
        )

        agg = totals.get(label)
        if agg is None:
            order.append(label)
            agg = {
                "count": 0,
                "total_cycles": 0,
                "total_duration_ns": 0,
                "min_cycles": cycles,
                "max_cycles": cycles,
            }
            totals[label] = agg
        agg["count"] += 1
        agg["total_cycles"] += cycles
        agg["total_duration_ns"] += duration_ns
        if cycles < agg["min_cycles"]:
            agg["min_cycles"] = cycles
        if cycles > agg["max_cycles"]:
            agg["max_cycles"] = cycles

    summary: list[dict[str, object]] = []
    for label in order:
        agg = totals[label]
        count = agg["count"]
        total_cycles = agg["total_cycles"]
        total_duration_ns = agg["total_duration_ns"]
        summary.append(
            {
                "label": label,
                "count": count,
                "total_cycles": total_cycles,
                "min_cycles": agg["min_cycles"],
                "max_cycles": agg["max_cycles"],
                "average_cycles": total_cycles // count,
                "total_duration_ns": total_duration_ns,
                "average_duration_ns": total_duration_ns // count,
            }
        )

    return {"samples": results, "summary": summary}
