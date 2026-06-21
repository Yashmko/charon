"""Tests for the advisory Annotation type and its read-only nature."""

from __future__ import annotations

import dataclasses

import pytest

from charon.model import (
    Annotation,
    Evidence,
    Finding,
    OwaspClass,
    Provenanced,
    ProvenanceError,
    Severity,
)
from charon.model.annotation import AnnotationKind


def _finding(evidence: Evidence) -> Finding:
    return Finding.create(
        rule_id="r",
        owasp_class=OwaspClass.API1_BOLA,
        severity=Severity.HIGH,
        subject={"path_template": Provenanced.observed("/api/invoices/{id}")},
        evidence=[evidence],
    )


def test_annotation_requires_inferred_content(evidence: Evidence) -> None:
    finding = _finding(evidence)
    with pytest.raises(ProvenanceError):
        Annotation(
            target_ref=finding.finding_id,
            kind=AnnotationKind.SEMANTIC_LABEL,
            content=Provenanced.derived("not advisory"),
        )


def test_annotation_attaches_by_reference_only(evidence: Evidence) -> None:
    finding = _finding(evidence)
    annotation = Annotation(
        target_ref=finding.finding_id,
        kind=AnnotationKind.SEMANTIC_LABEL,
        content=Provenanced.inferred("Invoice object"),
    )
    # The annotation only knows the target's content address; it holds no
    # reference that could mutate the finding.
    assert annotation.target_ref == finding.finding_id
    assert annotation.is_advisory
    assert not hasattr(annotation, "finding")


def test_annotation_can_label_disagreement_without_changing_finding(
    evidence: Evidence,
) -> None:
    finding = _finding(evidence)
    annotation = Annotation(
        target_ref=finding.finding_id,
        kind=AnnotationKind.DISAGREEMENT,
        content=Provenanced.inferred("LLM believes this is public"),
        disagrees_with_evidence=True,
    )
    assert annotation.disagrees_with_evidence
    # The finding is untouched: evidence remains authoritative.
    assert finding.evidence_ids == (evidence.evidence_id,)


def test_annotation_is_immutable(evidence: Evidence) -> None:
    finding = _finding(evidence)
    annotation = Annotation(
        target_ref=finding.finding_id,
        kind=AnnotationKind.EXPLANATION,
        content=Provenanced.inferred("because reasons"),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        annotation.target_ref = "sha256:other"  # type: ignore[misc]
