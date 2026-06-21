"""``Annotation``: advisory, LLM-sourced metadata attached by reference.

An :class:`Annotation` is the only ``Inferred`` type in the model. It attaches
advisory metadata (semantic label, ownership inference, summary, explanation)
*by reference* to a sealed ``Finding`` or ``Evidence``.

By construction an annotation has no power to mutate the finding set: it holds
only the content address of its target plus its own advisory payload. It can
record a disagreement with evidence, but evidence remains authoritative
(architecture invariant 4); the disagreement is retained as a labeled,
lower-trust note, never as a change to the finding.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from charon.model.addressing import ContentAddress, content_address
from charon.model.exceptions import ProvenanceError
from charon.model.provenance import Provenance, Provenanced

__all__ = ["AnnotationKind", "Annotation"]


class AnnotationKind(enum.Enum):
    """The kind of advisory metadata an annotation carries."""

    SEMANTIC_LABEL = "semantic_label"
    OWNERSHIP_INFERENCE = "ownership_inference"
    POLICY_SUMMARY = "policy_summary"
    EXPLANATION = "explanation"
    DISAGREEMENT = "disagreement"


@dataclass(frozen=True, slots=True)
class Annotation:
    """Advisory metadata attached by reference to a sealed artifact.

    The annotation references its target (a ``Finding`` or ``Evidence``) only
    by content address; it cannot reach into or alter that target. Its
    payload is always ``Inferred`` provenance.
    """

    #: Content address of the sealed Finding or Evidence this annotates.
    target_ref: ContentAddress
    kind: AnnotationKind
    #: The advisory content. Must be ``Inferred`` provenance.
    content: Provenanced[str]
    #: ``True`` when this annotation disagrees with deterministic evidence.
    #: Evidence still wins; this only labels the conflict.
    disagrees_with_evidence: bool = False
    annotation_id: ContentAddress = field(default="", compare=False)

    def __post_init__(self) -> None:
        if self.content.source is not Provenance.INFERRED:
            raise ProvenanceError(
                "Annotation content must be Inferred (advisory); got "
                f"{self.content.source.value!r}."
            )
        if not self.target_ref:
            raise ProvenanceError("Annotation requires a target_ref.")
        object.__setattr__(self, "annotation_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    @property
    def is_advisory(self) -> bool:
        """Annotations are always advisory; provided for symmetry/readability."""
        return True

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this annotation."""
        return {
            "type": "Annotation",
            "target_ref": self.target_ref,
            "kind": self.kind.value,
            "content": {
                "value": self.content.value,
                "source": self.content.source.value,
            },
            "disagrees_with_evidence": self.disagrees_with_evidence,
        }
