"""``Comparison`` and supporting diff types.

A :class:`Comparison` is a structured, deterministic diff of two responses
(status, headers, body, access decision). It references the inputs it
compared and has provenance ``Derived``.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from charon.model.addressing import ContentAddress, content_address
from charon.model.provenance import Provenance

__all__ = ["AccessDecision", "FieldDiff", "ResponseSnapshot", "Comparison"]


class AccessDecision(enum.Enum):
    """The deterministically-classified access outcome of a response.

    This classification is derived purely from observed/replayed response
    data (e.g. status code and body shape); it never consults an LLM.
    """

    GRANTED = "granted"
    DENIED = "denied"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class FieldDiff:
    """A single deterministic field-level difference between two responses."""

    location: str
    baseline_value: str | None
    other_value: str | None

    def to_canonical(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable view of this diff."""
        return {
            "location": self.location,
            "baseline_value": self.baseline_value,
            "other_value": self.other_value,
        }


@dataclass(frozen=True, slots=True)
class ResponseSnapshot:
    """A minimal, comparable view of one side of a comparison."""

    status_code: int
    access_decision: AccessDecision

    def to_canonical(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable view of this snapshot."""
        return {
            "status_code": self.status_code,
            "access_decision": self.access_decision.value,
        }


@dataclass(frozen=True, slots=True)
class Comparison:
    """Structured diff of two responses.

    References the two inputs it compared by their content addresses (the
    captured baseline and the replay result). Provenance is ``Derived``.
    """

    baseline_ref: ContentAddress
    other_ref: ContentAddress
    baseline: ResponseSnapshot
    other: ResponseSnapshot
    field_diffs: tuple[FieldDiff, ...] = ()
    comparison_id: ContentAddress = field(default="", compare=False)

    provenance: Provenance = field(default=Provenance.DERIVED, init=False)

    def __post_init__(self) -> None:
        ordered = tuple(
            sorted(
                self.field_diffs,
                key=lambda d: (d.location, d.baseline_value or "", d.other_value or ""),
            )
        )
        object.__setattr__(self, "field_diffs", ordered)
        object.__setattr__(self, "comparison_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    @property
    def differs(self) -> bool:
        """Return ``True`` if any structured difference was recorded."""
        return (
            bool(self.field_diffs)
            or self.baseline.status_code != self.other.status_code
            or self.baseline.access_decision != self.other.access_decision
        )

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this comparison."""
        return {
            "type": "Comparison",
            "baseline_ref": self.baseline_ref,
            "other_ref": self.other_ref,
            "baseline": self.baseline.to_canonical(),
            "other": self.other.to_canonical(),
            "field_diffs": [d.to_canonical() for d in self.field_diffs],
        }
