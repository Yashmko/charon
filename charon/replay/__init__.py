"""Deterministic HTTP(S) replay for Charon's core.

The ``replay`` module re-issues a captured exchange
(:class:`~charon.model.CapturedExchange`) under a configurable identity and
records the observable result as model artifacts
(:class:`~charon.model.ReplayRequest` and
:class:`~charon.model.ReplayResult`).

Design goals (see ``docs/architecture.md`` -> ``replay`` acceptance
criteria):

* Re-issues requests deterministically given the same target behavior.
* Captures and flags target-side nondeterminism rather than hiding it.
* Runs with no LLM present; nothing here is advisory.
* The HTTP client is hidden behind a small :class:`Transport` protocol so it
  can be swapped; downstream modules never import a concrete client.
* Authentication material lives only in runtime :class:`ReplayCredential`
  objects and is never persisted inside content-addressed artifacts.

This module deliberately performs no comparison, detection, evidence,
reporting, or enrichment. It only replays and records.
"""

from charon.replay.credential import ReplayCredential
from charon.replay.engine import ReplayEngine
from charon.replay.errors import (
    ReplayConnectionError,
    ReplayError,
    ReplayMalformedResponseError,
    ReplayTimeoutError,
    ReplayTransportError,
)
from charon.replay.result import ReplayExecution, ReplayFailure, ReplayFailureKind
from charon.replay.transport import (
    Transport,
    TransportRequest,
    TransportResponse,
)

__all__ = [
    "ReplayConnectionError",
    "ReplayCredential",
    "ReplayEngine",
    "ReplayError",
    "ReplayExecution",
    "ReplayFailure",
    "ReplayFailureKind",
    "ReplayMalformedResponseError",
    "ReplayTimeoutError",
    "ReplayTransportError",
    "Transport",
    "TransportRequest",
    "TransportResponse",
]
