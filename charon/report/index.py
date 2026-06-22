"""Read-only artifact resolver for report assembly.

Findings reference their supporting artifacts by content address. To render a
traceable report, the builder needs to resolve those addresses back to the
concrete objects. :class:`ArtifactIndex` is a simple, read-only lookup keyed
by content address. It never mutates the artifacts it indexes.
"""

from __future__ import annotations

from collections.abc import Iterable

from charon.model import (
    CapturedExchange,
    Comparison,
    Evidence,
    ReplayRequest,
    ReplayResult,
)

__all__ = ["ArtifactIndex"]


class ArtifactIndex:
    """A read-only content-address -> artifact resolver.

    Artifacts are registered up front; lookups return ``None`` when an
    address is unknown so the renderer can degrade gracefully (a missing
    artifact is reported as such rather than crashing the report).
    """

    def __init__(
        self,
        *,
        captured_exchanges: Iterable[CapturedExchange] = (),
        replay_requests: Iterable[ReplayRequest] = (),
        replay_results: Iterable[ReplayResult] = (),
        comparisons: Iterable[Comparison] = (),
        evidence: Iterable[Evidence] = (),
    ) -> None:
        self._exchanges = {e.exchange_id: e for e in captured_exchanges}
        self._requests = {r.request_id: r for r in replay_requests}
        self._results = {r.result_id: r for r in replay_results}
        self._comparisons = {c.comparison_id: c for c in comparisons}
        self._evidence = {e.evidence_id: e for e in evidence}

    def captured_exchange(self, ref: str) -> CapturedExchange | None:
        """Resolve a captured exchange by content address."""
        return self._exchanges.get(ref)

    def replay_request(self, ref: str) -> ReplayRequest | None:
        """Resolve a replay request by content address."""
        return self._requests.get(ref)

    def replay_result(self, ref: str) -> ReplayResult | None:
        """Resolve a replay result by content address."""
        return self._results.get(ref)

    def comparison(self, ref: str) -> Comparison | None:
        """Resolve a comparison by content address."""
        return self._comparisons.get(ref)

    def evidence(self, ref: str) -> Evidence | None:
        """Resolve an evidence artifact by content address."""
        return self._evidence.get(ref)
