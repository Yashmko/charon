"""Outcome types for a single replay execution.

A replay either produces a real HTTP response -- captured as a model
:class:`~charon.model.ReplayResult` -- or fails at the transport level. A
failure must never be coerced into a fake ``ReplayResult`` (that would
corrupt downstream evidence), so the engine returns a
:class:`ReplayExecution`: a ``ReplayResult`` on success or a typed
:class:`ReplayFailure` on error. The originating
:class:`~charon.model.ReplayRequest` is always present so the attempt is
traceable either way.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from charon.model import ReplayRequest, ReplayResult

__all__ = ["ReplayFailureKind", "ReplayFailure", "ReplayExecution"]


class ReplayFailureKind(enum.Enum):
    """Why a replay failed at the transport level."""

    TIMEOUT = "timeout"
    CONNECTION = "connection"
    MALFORMED_RESPONSE = "malformed_response"
    TRANSPORT = "transport"


@dataclass(frozen=True, slots=True)
class ReplayFailure:
    """A transport-level replay failure, recorded without faking a response.

    :param replay_request: The request that was attempted (content-addressed,
        secret-free).
    :param kind: The classified failure category.
    :param detail: A human-readable message from the transport. Not
        content-addressed; for diagnostics only.
    """

    replay_request: ReplayRequest
    kind: ReplayFailureKind
    detail: str

    @property
    def succeeded(self) -> bool:
        """Always ``False``; present for symmetry with successful executions."""
        return False


@dataclass(frozen=True, slots=True)
class ReplayExecution:
    """The result of one replay attempt.

    Exactly one of :attr:`result` (success) or :attr:`failure` (transport
    error) is set. :attr:`request` is always present.
    """

    request: ReplayRequest
    result: ReplayResult | None = None
    failure: ReplayFailure | None = None

    def __post_init__(self) -> None:
        if (self.result is None) == (self.failure is None):
            raise ValueError(
                "ReplayExecution must have exactly one of result or failure."
            )

    @property
    def succeeded(self) -> bool:
        """Return ``True`` if the replay produced a real HTTP response."""
        return self.result is not None
