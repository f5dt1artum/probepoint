import struct
import unittest

from probepoint.backtrace import BacktraceError
from probepoint.service import Service

STACK_BASE = 0x20000000


def build_stack(records: dict[int, tuple[int, int]], size: int) -> str:
    """Assemble a stack snapshot: {offset: (prev_fp, saved_lr)} over `size` bytes."""
    image = bytearray(size)
    for offset, (prev_fp, saved_lr) in records.items():
        image[offset : offset + 8] = struct.pack("<II", prev_fp, saved_lr)
    return bytes(image).hex()


def make_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "pc": 0x08000301,
        "sp": 0x1FFFFF00,
        "frame_pointer": STACK_BASE,
        "stack_base": STACK_BASE,
        "stack": build_stack(
            {
                0x00: (STACK_BASE + 0x10, 0x08001235),
                0x10: (STACK_BASE + 0x20, 0x08000101),
                0x20: (0, 0x08000021),
            },
            0x28,
        ),
        "symbols": [
            {"name": "main", "start": 0x08000100, "end": 0x08000200},
            {"name": "worker", "start": 0x08001200, "end": 0x08001300},
        ],
    }
    body.update(overrides)
    return body


class BacktraceWalkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = Service()

    def test_complete_chain_with_symbols(self) -> None:
        result = self.service.backtrace(make_body())
        self.assertEqual(result["stop_reason"], "complete")
        frames = result["frames"]
        self.assertEqual(len(frames), 3)
        self.assertEqual(
            frames[0],
            {
                "level": 0,
                "address": 0x08000300,  # Thumb bit cleared
                "sp": 0x1FFFFF00,
                "frame_pointer": STACK_BASE,
                "symbol": None,
                "offset": None,
            },
        )
        self.assertEqual(
            frames[1],
            {
                "level": 1,
                "address": 0x08001234,
                "sp": STACK_BASE + 0x08,
                "frame_pointer": STACK_BASE + 0x10,
                "symbol": "worker",
                "offset": 0x34,
            },
        )
        self.assertEqual(
            frames[2],
            {
                "level": 2,
                "address": 0x08000100,
                "sp": STACK_BASE + 0x18,
                "frame_pointer": STACK_BASE + 0x20,
                "symbol": "main",
                "offset": 0,
            },
        )

    def test_zero_initial_frame_pointer_completes_immediately(self) -> None:
        result = self.service.backtrace(make_body(frame_pointer=0))
        self.assertEqual(result["stop_reason"], "complete")
        self.assertEqual(len(result["frames"]), 1)
        self.assertEqual(result["frames"][0]["frame_pointer"], 0)

    def test_max_frames_stops_unwind(self) -> None:
        result = self.service.backtrace(make_body(max_frames=2))
        self.assertEqual(result["stop_reason"], "max_frames")
        self.assertEqual([f["level"] for f in result["frames"]], [0, 1])

    def test_max_frames_default_is_64(self) -> None:
        # Build a 100-deep chain; the default cap must cut it at 64.
        records = {
            i * 8: (STACK_BASE + (i + 1) * 8, 0x08000101) for i in range(100)
        }
        result = self.service.backtrace(
            make_body(stack=build_stack(records, 100 * 8 + 8))
        )
        self.assertEqual(result["stop_reason"], "max_frames")
        self.assertEqual(len(result["frames"]), 64)

    def test_misaligned_frame_pointer_is_invalid_chain(self) -> None:
        result = self.service.backtrace(make_body(frame_pointer=STACK_BASE + 2))
        self.assertEqual(result["stop_reason"], "invalid_chain")
        self.assertEqual(len(result["frames"]), 1)

    def test_non_increasing_chain_is_invalid(self) -> None:
        body = make_body(
            stack=build_stack({0x00: (STACK_BASE, 0x08000101)}, 0x08)
        )
        result = self.service.backtrace(body)
        self.assertEqual(result["stop_reason"], "invalid_chain")
        self.assertEqual(len(result["frames"]), 1)

    def test_cycle_is_invalid_chain(self) -> None:
        body = make_body(
            stack=build_stack(
                {
                    0x00: (STACK_BASE + 0x10, 0x08000101),
                    0x10: (STACK_BASE + 0x10, 0x08000101),  # points at itself
                },
                0x18,
            )
        )
        result = self.service.backtrace(body)
        self.assertEqual(result["stop_reason"], "invalid_chain")
        self.assertEqual(len(result["frames"]), 2)

    def test_record_outside_snapshot_is_stack_exhausted(self) -> None:
        body = make_body(frame_pointer=STACK_BASE + 0x1000)
        result = self.service.backtrace(body)
        self.assertEqual(result["stop_reason"], "stack_exhausted")
        self.assertEqual(len(result["frames"]), 1)

    def test_partially_covered_record_is_stack_exhausted(self) -> None:
        # fp inside the snapshot but the 8-byte record crosses the top edge.
        body = make_body(
            frame_pointer=STACK_BASE + 0x04,
            stack=build_stack({}, 0x08),
        )
        result = self.service.backtrace(body)
        self.assertEqual(result["stop_reason"], "stack_exhausted")
        self.assertEqual(len(result["frames"]), 1)

    def test_empty_symbols_yield_null_fields(self) -> None:
        result = self.service.backtrace(make_body(symbols=[]))
        self.assertEqual(result["stop_reason"], "complete")
        for frame in result["frames"]:
            self.assertIsNone(frame["symbol"])
            self.assertIsNone(frame["offset"])


class BacktraceValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = Service()

    def assert_code(self, code: str, body: object) -> None:
        with self.assertRaises(BacktraceError) as ctx:
            self.service.backtrace(body)
        self.assertEqual(ctx.exception.code, code)

    def test_non_object_body(self) -> None:
        self.assert_code("invalid_request", [1, 2, 3])
        self.assert_code("invalid_request", None)

    def test_missing_field(self) -> None:
        body = make_body()
        del body["pc"]
        self.assert_code("invalid_field", body)

    def test_extra_field(self) -> None:
        self.assert_code("invalid_field", make_body(bogus=1))

    def test_uint32_type_and_range(self) -> None:
        for field in ("pc", "sp", "frame_pointer", "stack_base"):
            self.assert_code("invalid_field", make_body(**{field: True}))
            self.assert_code("invalid_field", make_body(**{field: -1}))
            self.assert_code("invalid_field", make_body(**{field: 1 << 32}))
            self.assert_code("invalid_field", make_body(**{field: "0x10"}))

    def test_bad_hex_stack(self) -> None:
        self.assert_code("invalid_field", make_body(stack="abc"))
        self.assert_code("invalid_field", make_body(stack="zz"))
        self.assert_code("invalid_field", make_body(stack=12))

    def test_oversized_stack(self) -> None:
        self.assert_code("invalid_field", make_body(stack="00" * (1 << 20 | 1)))

    def test_stack_range_overflow(self) -> None:
        self.assert_code(
            "invalid_field", make_body(stack_base=0xFFFFFFFF, stack="0000")
        )
        # Exactly reaching the top of the address space is fine.
        result = self.service.backtrace(
            make_body(stack_base=0xFFFFFFFF - 7, stack="00" * 8)
        )
        self.assertEqual(result["stop_reason"], "stack_exhausted")

    def test_symbol_validation(self) -> None:
        self.assert_code("invalid_field", make_body(symbols="main"))
        self.assert_code("invalid_field", make_body(symbols=[{"name": "a", "start": 0}]))
        self.assert_code(
            "invalid_field",
            make_body(symbols=[{"name": "a", "start": 0, "end": 1, "x": 1}]),
        )
        self.assert_code(
            "invalid_field",
            make_body(symbols=[{"name": "", "start": 0, "end": 1}]),
        )
        self.assert_code(
            "invalid_field",
            make_body(symbols=[{"name": "a", "start": 5, "end": 5}]),
        )
        self.assert_code(
            "invalid_field",
            make_body(
                symbols=[
                    {"name": "a", "start": 0, "end": 0x100},
                    {"name": "b", "start": 0x80, "end": 0x200},
                ]
            ),
        )

    def test_adjacent_symbols_do_not_overlap(self) -> None:
        result = self.service.backtrace(
            make_body(
                symbols=[
                    {"name": "a", "start": 0x08000300, "end": 0x08000400},
                    {"name": "b", "start": 0x08000400, "end": 0x08000500},
                ]
            )
        )
        self.assertEqual(result["frames"][0]["symbol"], "a")
        self.assertEqual(result["frames"][0]["offset"], 0)

    def test_max_frames_validation(self) -> None:
        self.assert_code("invalid_field", make_body(max_frames=0))
        self.assert_code("invalid_field", make_body(max_frames=257))
        self.assert_code("invalid_field", make_body(max_frames=True))
        self.assert_code("invalid_field", make_body(max_frames="64"))


if __name__ == "__main__":
    unittest.main()
