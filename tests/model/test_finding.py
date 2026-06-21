"""Tests for the evidence-backed Finding invariant."""

from __future__ import annotations

import dataclasses

import pytest

from charon.model import (
    Evidence,
    Finding,
    InvalidFindingError,
    OwaspClass,
    Provenance,
    Provenanced,
    ProvenanceError,
    Severity,
)


def _subject() -> dict[str, Provenanced[str]]:
    return {
        "path_template": Provenanced.observed("/api/invoices/{id}"),
        "access_decision": Provenanced.derived("granted"),
    }


def test_finding_create_requires_evidence_object(evidence: Evidence) -> None:
    finding = Finding.create(
        rule_id="bola.cross-account-read",
        owasp_class=OwaspClass.API1_BOLA,
        severity=Severity.HIGH,
        subject=_subject(),
        evidence=[evidence],
    )
    assert finding.evidence_ids == (evidence.evidence_id,)
    assert finding.finding_id.startswith("sha256:")


def test_finding_create_rejects_empty_evidence() -> None:
    with pytest.raises(InvalidFindingError):
        Finding.create(
            rule_id="r",
            owasp_class=OwaspClass.API1_BOLA,
            severity=Severity.HIGH,
            subject=_subject(),
            evidence=[],
        )


def test_finding_direct_construction_rejects_empty_evidence_ids() -> None:
    with pytest.raises(InvalidFindingError):
        Finding(
            rule_id="r",
            owasp_class=OwaspClass.API1_BOLA,
            severity=Severity.HIGH,
            subject=_subject(),
            evidence_ids=(),
        )


def test_finding_rejects_inferred_subject_field(evidence: Evidence) -> None:
    with pytest.raises(ProvenanceError):
        Finding.create(
            rule_id="r",
            owasp_class=OwaspClass.API1_BOLA,
            severity=Severity.HIGH,
            subject={"semantic_name": Provenanced.inferred("Invoice")},
            evidence=[evidence],
        )


def test_finding_is_immutable(evidence: Evidence) -> None:
    finding = Finding.create(
        rule_id="r",
        owasp_class=OwaspClass.API1_BOLA,
        severity=Severity.HIGH,
        subject=_subject(),
        evidence=[evidence],
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.severity = Severity.LOW  # type: ignore[misc]


def test_finding_id_is_deterministic(evidence: Evidence) -> None:
    kwargs = dict(
        rule_id="r",
        owasp_class=OwaspClass.API1_BOLA,
        severity=Severity.HIGH,
        subject=_subject(),
        evidence=[evidence],
    )
    assert Finding.create(**kwargs).finding_id == Finding.create(**kwargs).finding_id


def test_finding_core_fields_are_deterministic_provenance(evidence: Evidence) -> None:
    finding = Finding.create(
        rule_id="r",
        owasp_class=OwaspClass.API1_BOLA,
        severity=Severity.HIGH,
        subject=_subject(),
        evidence=[evidence],
    )
    for tagged in finding.subject.values():
        assert tagged.source is not Provenance.INFERRED
