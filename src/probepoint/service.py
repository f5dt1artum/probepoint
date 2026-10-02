"""Core service surface for ProbePoint.

The frozen baseline only reports process health. Later work adds the real
capabilities described in README.md behind this module; keep the public
surface here backward compatible.
"""

from __future__ import annotations

from . import __version__
from .frames import decode_frame, encode_frame


class Service:
    """Health reporting plus the v1 debug protocol frame codec."""

    name = "probepoint"
    version = __version__

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def encode_frame(self, body: object) -> dict[str, str]:
        return encode_frame(body)

    def decode_frame(self, body: object) -> dict[str, object]:
        return decode_frame(body)
