"""Exceptions raised by the capture subsystem."""

from __future__ import annotations

__all__ = ["CaptureError", "MalformedExchangeError"]


class CaptureError(Exception):
    """Base class for all errors raised by the capture subsystem."""


class MalformedExchangeError(CaptureError):
    """Raised when a backend yields input that cannot form a valid exchange.

    Capture is at the edge of the deterministic core: malformed real-world
    input is expected, so it is rejected with a clear, typed error rather
    than producing a corrupt or non-reproducible artifact.
    """
