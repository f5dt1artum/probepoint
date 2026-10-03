import json
import struct
import unittest
import urllib.error
import urllib.request

from probepoint.server import make_server

STACK_BASE = 0x20000000


def build_stack(records: dict[int, tuple[int, int]], size: int = 0x40) -> str:
    """Render a stack snapshot; records maps fp -> (previous_fp, saved_lr)."""
    buf = bytearray(size)
    for fp, (previous_fp, saved_lr) in records.items():
        offset = fp - STACK_BASE
        buf[offset : offset + 8] = struct.pack("<II", previous_fp, saved_lr)
    return bytes(buf).hex()


class BacktraceHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        import threading

        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def post(self, path: str, raw: bytes) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def backtrace(self, **overrides: object) -> tuple[int, dict]:
        body: dict[str, object] = {
            "pc": 0x08000031,
            "sp": 0x20000008,
            "frame_pointer": 0x20000010,
            "stack_base": STACK_BASE,
            "stack": build_stack(
                {
                    0x20000010: (0x20000020, 0x08000101),
                    0x20000020: (0x00000000, 0x08000201),
                }
            ),
            "symbols": [
                {"name": "main", "start": 0x08000030, "end": 0x08000050},
                {"name": "foo", "start": 0x08000100, "end": 0x08000120},
                {"name": "bar", "start": 0x08000200, "end": 0x08000210},
            ],
        }
        body.update(overrides)
        return self.post("/v1/backtrace", json.dumps(body).encode("utf-8"))


class UnwindTest(BacktraceHttpTest):
    def test_complete_chain(self) -> None:
        status, body = self.backtrace()
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "complete")
        self.assertEqual(len(body["frames"]), 3)

        frame0, frame1, frame2 = body["frames"]
        self.assertEqual(
            frame0,
            {
                "level": 0,
                "address": 0x08000030,  # Thumb bit cleared
                "sp": 0x20000008,
                "frame_pointer": 0x20000010,
                "symbol": "main",
                "offset": 0,
            },
        )
        self.assertEqual(
            frame1,
            {
                "level": 1,
                "address": 0x08000100,
                "sp": 0x20000018,  # caller record address + 8
                "frame_pointer": 0x20000020,
                "symbol": "foo",
                "offset": 0,
            },
        )
        self.assertEqual(frame2["level"], 2)
        self.assertEqual(frame2["address"], 0x08000200)
        self.assertEqual(frame2["sp"], 0x20000028)
        self.assertEqual(frame2["frame_pointer"], 0)
        self.assertEqual(frame2["symbol"], "bar")
        self.assertEqual(frame2["offset"], 0)

    def test_symbol_offset_and_miss(self) -> None:
        status, body = self.backtrace(
            pc=0x08000034,  # main + 4
            stack=build_stack({0x20000010: (0x20000020, 0x09000101)}),  # outside all symbols
        )
        self.assertEqual(status, 200)
        frame0, frame1 = body["frames"][:2]
        self.assertEqual(frame0["symbol"], "main")
        self.assertEqual(frame0["offset"], 4)
        self.assertIsNone(frame1["symbol"])
        self.assertIsNone(frame1["offset"])

    def test_frame_pointer_zero_completes_immediately(self) -> None:
        status, body = self.backtrace(frame_pointer=0)
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "complete")
        self.assertEqual(len(body["frames"]), 1)

    def test_max_frames_limit(self) -> None:
        status, body = self.backtrace(max_frames=2)
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "max_frames")
        self.assertEqual([f["level"] for f in body["frames"]], [0, 1])

    def test_max_frames_one_keeps_first_frame(self) -> None:
        status, body = self.backtrace(max_frames=1)
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "max_frames")
        self.assertEqual(len(body["frames"]), 1)

    def test_misaligned_frame_pointer(self) -> None:
        status, body = self.backtrace(frame_pointer=0x20000012)
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "invalid_chain")
        self.assertEqual(len(body["frames"]), 1)

    def test_chain_must_advance_upward(self) -> None:
        status, body = self.backtrace(
            stack=build_stack({0x20000010: (0x20000010, 0x08000101)})  # self-cycle
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "invalid_chain")
        self.assertEqual(len(body["frames"]), 1)

    def test_chain_moving_downward_is_invalid(self) -> None:
        status, body = self.backtrace(
            stack=build_stack({0x20000010: (0x20000008, 0x08000101)})
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "invalid_chain")
        self.assertEqual(len(body["frames"]), 1)

    def test_record_outside_snapshot(self) -> None:
        status, body = self.backtrace(frame_pointer=0x20001000)
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "stack_exhausted")
        self.assertEqual(len(body["frames"]), 1)

    def test_partial_record_is_not_a_frame(self) -> None:
        # Only 4 of the 8 record bytes remain inside the snapshot.
        status, body = self.backtrace(
            frame_pointer=STACK_BASE + 0x3C,
            stack=build_stack({}, size=0x40),
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "stack_exhausted")
        self.assertEqual(len(body["frames"]), 1)

    def test_empty_stack_and_empty_symbols(self) -> None:
        status, body = self.backtrace(stack="", symbols=[])
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "stack_exhausted")
        self.assertEqual(len(body["frames"]), 1)
        self.assertIsNone(body["frames"][0]["symbol"])

    def test_stack_may_reach_top_of_address_space(self) -> None:
        stack_base = 0xFFFFFFF8
        status, body = self.backtrace(
            frame_pointer=stack_base,
            stack_base=stack_base,
            stack=struct.pack("<II", 0, 0x08000201).hex(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["stop_reason"], "complete")
        self.assertEqual(len(body["frames"]), 2)
        self.assertEqual(body["frames"][1]["sp"], 0x100000000)


class ValidationTest(BacktraceHttpTest):
    def assert_invalid_field(self, **overrides: object) -> None:
        status, body = self.backtrace(**overrides)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_non_object_body(self) -> None:
        status, body = self.post("/v1/backtrace", b"[1, 2, 3]")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_unparseable_body(self) -> None:
        status, body = self.post("/v1/backtrace", b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_missing_field(self) -> None:
        status, body = self.backtrace(pc=None)
        self.assertEqual(status, 400)  # None is not a u32
        self.assertEqual(body["error"]["code"], "invalid_field")

        status, body = self.post(
            "/v1/backtrace",
            json.dumps({"pc": 0, "sp": 0, "frame_pointer": 0}).encode("utf-8"),
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_field")

    def test_extra_field(self) -> None:
        self.assert_invalid_field(bogus=1)

    def test_integer_fields_must_be_u32(self) -> None:
        for field in ("pc", "sp", "frame_pointer", "stack_base"):
            self.assert_invalid_field(**{field: -1})
            self.assert_invalid_field(**{field: 1 << 32})
            self.assert_invalid_field(**{field: True})
            self.assert_invalid_field(**{field: "0"})

    def test_stack_hex_and_size(self) -> None:
        self.assert_invalid_field(stack="abc")  # odd length
        self.assert_invalid_field(stack="zz")
        self.assert_invalid_field(stack=12)
        self.assert_invalid_field(stack="00" * (1 << 20) + "00")  # over 1 MiB

    def test_stack_address_overflow(self) -> None:
        self.assert_invalid_field(stack_base=0xFFFFFFF9, stack="00" * 8)
        self.assert_invalid_field(stack_base=0xFFFFFFFF, stack="00" * 2)

    def test_max_frames_range(self) -> None:
        self.assert_invalid_field(max_frames=0)
        self.assert_invalid_field(max_frames=257)
        self.assert_invalid_field(max_frames=True)
        self.assert_invalid_field(max_frames="64")

    def test_symbols_must_be_array_of_objects(self) -> None:
        self.assert_invalid_field(symbols={})
        self.assert_invalid_field(symbols=["main"])
        self.assert_invalid_field(symbols=[{"name": "a", "start": 0}])
        self.assert_invalid_field(symbols=[{"name": "a", "start": 0, "end": 1, "x": 1}])

    def test_symbol_name_and_range(self) -> None:
        self.assert_invalid_field(symbols=[{"name": "", "start": 0, "end": 1}])
        self.assert_invalid_field(symbols=[{"name": 1, "start": 0, "end": 1}])
        self.assert_invalid_field(symbols=[{"name": "a", "start": 1, "end": 1}])
        self.assert_invalid_field(symbols=[{"name": "a", "start": 2, "end": 1}])
        self.assert_invalid_field(symbols=[{"name": "a", "start": -1, "end": 1}])
        self.assert_invalid_field(symbols=[{"name": "a", "start": 0, "end": 1 << 32}])

    def test_symbols_must_not_overlap(self) -> None:
        self.assert_invalid_field(
            symbols=[
                {"name": "a", "start": 0x100, "end": 0x200},
                {"name": "b", "start": 0x1FF, "end": 0x300},
            ]
        )
        # Nested ranges overlap too.
        self.assert_invalid_field(
            symbols=[
                {"name": "a", "start": 0x100, "end": 0x300},
                {"name": "b", "start": 0x150, "end": 0x200},
            ]
        )
        # Adjacent ranges are fine.
        status, _ = self.backtrace(
            symbols=[
                {"name": "a", "start": 0x100, "end": 0x200},
                {"name": "b", "start": 0x200, "end": 0x300},
            ]
        )
        self.assertEqual(status, 200)

    def test_backtrace_does_not_touch_breakpoints(self) -> None:
        status, created = self.post(
            "/v1/breakpoints",
            json.dumps({"kind": "execute", "address": 0x08000030, "enabled": True}).encode(),
        )
        self.assertEqual(status, 201)
        status, _ = self.backtrace()
        self.assertEqual(status, 200)
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/breakpoints")
        with urllib.request.urlopen(req) as resp:
            listed = json.loads(resp.read())
        self.assertEqual(listed, [created])


if __name__ == "__main__":
    unittest.main()
