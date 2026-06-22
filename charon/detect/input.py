"""Input bundle for deterministic detection.

A :class:`~charon.model.Comparison` only holds *content addresses* of the
artifacts it compared. To both evaluate rules and assemble the minimal
backing :class:`~charon.model.Evidence`, the detector needs the concrete
source artifacts. :class:`DetectionInput` bundles a comparison with the
baseline :class:`~charon.model.CapturedExchange` and the
:class:`~charon.model.ReplayRequest` / :class:`~charon.model.ReplayResult`
that produced the "other" side of the comparison.

This is deterministic plumbing only: the detector reads these artifacts, it
never mutates them, and nothing here consults an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass

from charon.model import (
    CapturedExchange,
    Comparison,
    ReplayRequest,
    ReplayResult,
)

__all__ = ["DetectionInput"]


@dataclass(frozen=True, slots=True)
class DetectionInput:
    """A comparison plus the concrete artifacts that produced it.

    :param comparison: The structured diff emitted by ``compare``.
    :param baseline_exchange: The captured baseline exchange
        (``comparison.baseline_ref == baseline_exchange.exchange_id``).
    :param replay_request: The replay request that produced the other side.
    :param replay_result: The replay result that produced the other side
        (``comparison.other_ref == replay_result.result_id``).
    """

    comparison: Comparison
    baseline_exchange: CapturedExchange
    replay_request: ReplayRequest
    replay_result: ReplayResult

    def __post_init__(self) -> None:
        # Cheap, deterministic consistency checks: the bundle must actually
        # describe one coherent comparison, or rule evaluation would reason
        # over mismatched artifacts.
        if self.comparison.baseline_ref != self.baseline_exchange.exchange_id:
            raise ValueError(
                "DetectionInput baseline_exchange does not match "
                "comparison.baseline_ref."
            )
        if self.comparison.other_ref != self.replay_result.result_id:
            raise ValueError(
                "DetectionInput replay_result does not match "
                "comparison.other_ref."
            )
        if self.replay_result.replay_request_id != self.replay_request.request_id:
            raise ValueError(
                "DetectionInput replay_result does not match replay_request."
            )

    @property
    def is_cross_identity(self) -> bool:
        """Return ``True`` if the replay ran under a different identity.

        Cross-identity replay is the precondition for every authorization
        finding: replaying as the *same* account proves nothing about access
        control. The comparison is between the baseline account label and the
        replay identity label.
        """
        return (
            self.replay_request.identity.label
            != self.baseline_exchange.account_label
        )
