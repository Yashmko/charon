"""``Finding``: a detected authorization issue, backed by evidence.

The central invariant of the model lives here: **a ``Finding`` cannot be
constructed without at least one real ``Evidence`` object**, enforced at the
type level rather than by convention (``docs/data-model.md``).

The ``Finding`` stores a non-empty tuple of concrete
:class:`~charon.model.evidence.Evidence` objects. There is no constructor
path that accepts bare evidence-id strings, so a caller cannot mint a finding
from a fabricated, unbacked id. ``evidence_ids`` is exposed as a derived,
read-only view of the attached evidence for traceability and addressing.

Finding core (subject) fields may only carry deterministic provenance
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

    Holds no inline prose-as-proof: proof lives in the attached ``Evidence``
    objects. The ``evidence`` tuple is guaranteed to be non-empty and to
    contain only real :class:`Evidence` instances by construction; there is
    no way to build a ``Finding`` from a fabricated id string.

    Use :meth:`create` for an ergonomic, keyword-only constructor. Direct
    construction is supported too, but it still requires real ``Evidence``
    objects via the ``evidence`` field.
    """

    rule_id: str
    owasp_class: OwaspClass
    severity: Severity
    #: Identifiers (path templates, fields, etc.) the finding concerns, each
    #: provenance-tagged. Must all be deterministic.
    subject: Mapping[str, Provenanced[str]]
    #: The concrete evidence backing this finding. MUST be a non-empty tuple
    #: of real :class:`Evidence` objects.
    evidence: tuple[Evidence, ...]
    finding_id: ContentAddress = field(default="", compare=False)

    def __post_init__(self) -> None:
        evidence = tuple(self.evidence)
        if not evidence:
            raise InvalidFindingError(
                "A Finding requires at least one Evidence object; "
                "evidence-backed findings are an architectural invariant."
            )
        for item in evidence:
            if not isinstance(item, Evidence):
                raise InvalidFindingError(
                    "A Finding must be backed by real Evidence objects; got "
                    f"{type(item).__name__}. Evidence cannot be fabricated "
                    "from an id string."
                )
        for key, tagged in self.subject.items():
            if not isinstance(tagged, Provenanced):
                raise ProvenanceError(
                    f"Finding subject {key!r} must be Provenanced; "
                    f"got {type(tagged).__name__}."
                )
            _require_deterministic(key, tagged)
        # Deduplicate evidence by content address while preserving a stable,
        # sorted order so the finding id is a deterministic function of
        # content.
        deduped = {e.evidence_id: e for e in evidence}
        ordered = tuple(deduped[k] for k in sorted(deduped))
        object.__setattr__(self, "evidence", ordered)
        object.__setattr__(self, "subject", dict(self.subject))
        object.__setattr__(self, "finding_id", self._compute_id())

    @property
    def evidence_ids(self) -> tuple[ContentAddress, ...]:
        """Content addresses of the backing evidence (read-only, derived)."""
        return tuple(e.evidence_id for e in self.evidence)

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

        Requiring real evidence objects (rather than id strings) makes it
        impossible to create a finding without genuinely-assembled evidence.

        :raises InvalidFindingError: if ``evidence`` yields no items, or any
            item is not a real :class:`Evidence` instance.
        """
        return cls(
            rule_id=rule_id,
            owasp_class=owasp_class,
            severity=severity,
            subject=subject,
            evidence=tuple(evidence),
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
