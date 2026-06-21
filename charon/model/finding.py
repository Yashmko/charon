"""``Finding``: a detected authorization issue, backed by evidence.

The central invariant of the model lives here: **a ``Finding`` cannot be
constructed without at least one ``Evidence`` reference**, enforced at the
type level rather than by convention (``docs/data-model.md``).

Two defenses combine to make an invalid finding impossible-to-very-hard to
build:

#. The dataclass rejects an empty ``evidence_ids`` tuple in
   ``__post_init__``.
#. The :meth:`Finding.create` constructor requires real
   :class:`~charon.model.evidence.Evidence` *objects* (not bare strings),
   so a caller cannot fabricate a plausible-looking evidence id by hand.

Finding core fields may only carry deterministic provenance
(``Observed`` / ``Replayed`` / ``Derived``); an ``Inferred`` value is
rejected, because LLM output is advisory and never proof.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from charon.model.addressing import ContentAddress, content_address
from charon.model.evidence import Evidence
from charon.model.exceptions import InvalidFindingError, ProvenanceError
from charon.model.provenance import (
    DETERMINISTIC_PROVENANCE,
    Provenanced,
)

__all__ = ["OwaspClass", "Severity", "Finding"]


class OwaspClass(enum.Enum):
    """OWASP API Security Top 10 (2023) classes relevant to v1."""

    API1_BOLA = "API1"
    API3_BOPLA = "API3"
    API5_BFLA = "API5"


class Severity(enum.Enum):
    """Deterministically-assigned severity for a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _require_deterministic(name: str, tagged: Provenanced[Any]) -> None:
    """Reject any finding field tagged with advisory (LLM) provenance."""
    if tagged.source not in DETERMINISTIC_PROVENANCE:
        raise ProvenanceError(
            f"Finding field {name!r} must be deterministic "
            f"(Observed/Replayed/Derived), got {tagged.source.value!r}."
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected authorization issue produced solely by ``detect``.

    Holds no inline prose-as-proof: proof lives in referenced ``Evidence``.
    The ``evidence_ids`` tuple is guaranteed non-empty by construction.

    Prefer :meth:`create`, which requires real ``Evidence`` objects and so
    makes it impossible to mint a finding from a fabricated id string.
    """

    rule_id: str
    owasp_class: OwaspClass
    severity: Severity
    #: Identifiers (path templates, fields, etc.) the finding concerns, each
    #: provenance-tagged. Must all be deterministic.
    subject: Mapping[str, Provenanced[str]]
    #: Content addresses of the supporting evidence. MUST be non-empty.
    evidence_ids: tuple[ContentAddress, ...]
    finding_id: ContentAddress = field(default="", compare=False)

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise InvalidFindingError(
                "A Finding requires at least one Evidence reference; "
                "evidence-backed findings are an architectural invariant."
            )
        for key, tagged in self.subject.items():
            if not isinstance(tagged, Provenanced):
                raise ProvenanceError(
                    f"Finding subject {key!r} must be Provenanced; "
                    f"got {type(tagged).__name__}."
                )
            _require_deterministic(key, tagged)
        # Freeze the subject mapping and normalize evidence id ordering so the
        # finding id is a deterministic function of content.
        object.__setattr__(self, "subject", dict(self.subject))
        object.__setattr__(self, "evidence_ids", tuple(sorted(set(self.evidence_ids))))
        object.__setattr__(self, "finding_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        owasp_class: OwaspClass,
        severity: Severity,
        subject: Mapping[str, Provenanced[str]],
        evidence: Iterable[Evidence],
    ) -> "Finding":
        """Construct a finding from concrete :class:`Evidence` objects.

        This is the preferred constructor. Requiring real evidence objects
        (rather than id strings) makes it impossible to create a finding
        without genuinely-assembled evidence.

        :raises InvalidFindingError: if ``evidence`` yields no items.
        """
        evidence_ids = tuple(e.evidence_id for e in evidence)
        if not evidence_ids:
            raise InvalidFindingError(
                "Finding.create requires at least one Evidence object."
            )
        return cls(
            rule_id=rule_id,
            owasp_class=owasp_class,
            severity=severity,
            subject=subject,
            evidence_ids=evidence_ids,
        )

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this finding."""
        return {
            "type": "Finding",
            "rule_id": self.rule_id,
            "owasp_class": self.owasp_class.value,
            "severity": self.severity.value,
            "subject": {
                key: {"value": tagged.value, "source": tagged.source.value}
                for key, tagged in sorted(self.subject.items())
            },
            "evidence_ids": list(self.evidence_ids),
        }
