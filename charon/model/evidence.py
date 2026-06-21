"""``Evidence``: the assembled, content-addressed proof artifact.

An :class:`Evidence` references the concrete artifacts that produced it: the
captured exchange id(s), the replay request/result pair(s), and the
triggering comparison. It is the only thing a :class:`~charon.model.finding.
Finding` is permitted to point to as proof. Provenance is ``Derived``.

The audit path the architecture requires is:

    Finding -> Evidence -> Comparison -> (ReplayRequest, ReplayResult)
            -> CapturedExchange

No link in that chain may be LLM-generated, which is why ``Evidence`` only
holds content addresses of deterministic artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from charon.model.addressing import ContentAddress, content_address
from charon.model.exceptions import ModelError
from charon.model.provenance import Provenance

__all__ = ["Evidence"]


@dataclass(frozen=True, slots=True)
class Evidence:
    """Assembled, content-addressed proof artifact for a finding.

    References (by content address) the concrete deterministic artifacts that
    produced it. At least one captured exchange and the triggering comparison
    are required so that the evidence chain always terminates at raw observed
    bytes.
    """

    #: The comparison whose result triggered the rule. Required.
    comparison_ref: ContentAddress
    #: Captured exchange ids underpinning the evidence. At least one required.
    captured_exchange_refs: tuple[ContentAddress, ...]
    #: Replay (request_id, result_id) pairs involved, if any.
    replay_pairs: tuple[tuple[ContentAddress, ContentAddress], ...] = ()
    evidence_id: ContentAddress = field(default="", compare=False)

    provenance: Provenance = field(default=Provenance.DERIVED, init=False)

    def __post_init__(self) -> None:
        if not self.comparison_ref:
            raise ModelError("Evidence requires a triggering comparison_ref.")
        if not self.captured_exchange_refs:
            raise ModelError(
                "Evidence requires at least one captured_exchange_ref so the "
                "audit chain terminates at observed bytes."
            )
        object.__setattr__(
            self,
            "captured_exchange_refs",
            tuple(sorted(self.captured_exchange_refs)),
        )
        object.__setattr__(self, "replay_pairs", tuple(sorted(self.replay_pairs)))
        object.__setattr__(self, "evidence_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this evidence."""
        return {
            "type": "Evidence",
            "comparison_ref": self.comparison_ref,
            "captured_exchange_refs": list(self.captured_exchange_refs),
            "replay_pairs": [list(p) for p in self.replay_pairs],
        }
