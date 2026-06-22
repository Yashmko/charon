"""Exceptions raised by the replay subsystem.

Transport-level failures are surfaced as typed exceptions internally and then
captured into a deterministic :class:`~charon.replay.result.ReplayFailure`
record by the engine, so a failed network call never fabricates or corrupts
model evidence.
"""

from __future__ import annotations

__all__ = [
    "ReplayError",
    "ReplayTransportError",
    "ReplayTimeoutError",
    "ReplayConnectionError",
    "ReplayMalformedResponseError",
]


class ReplayError(Exception):
    """Base class for all errors raised by the replay subsystem."""


class ReplayTransportError(ReplayError):
    """A generic transport failure not covered by a more specific subclass."""


class ReplayTimeoutError(ReplayTransportError):
    """The transport timed out waiting for the target."""


class ReplayConnectionError(ReplayTransportError):
    """The transport could not establish a connection to the target."""


class ReplayMalformedResponseError(ReplayTransportError):
    """The target returned a response the transport could not parse."""
