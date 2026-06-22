"""Tests for the DetectionEngine: findings, evidence, determinism."""

from __future__ import annotations

from charon.detect import DetectionEngine, DetectionInput
from charon.model import Finding, OwaspClass, Provenance

from tests.detect.conftest import make_input


def test_engine_emits_evidence_backed_finding(
    bola_input: DetectionInput,
) -> None:
    findings = DetectionEngine().detect([bola_input])
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.owasp_class is OwaspClass.API1_BOLA
    # Backed by real evidence.
    assert len(finding.evidence) == 1
    evidence = finding.evidence[0]
    # Full traceability: evidence -> comparison / baseline / replay pair.
    assert evidence.comparison_ref == bola_input.comparison.comparison_id
    assert (
        bola_input.baseline_exchange.exchange_id
        in evidence.captured_exchange_refs
    )
    assert (
        bola_input.replay_request.request_id,
        bola_input.replay_result.result_id,
    ) in evidence.replay_pairs


def test_finding_subject_has_no_inferred_provenance(
    bola_input: DetectionInput,
) -> None:
    (finding,) = DetectionEngine().detect([bola_input])
    for tagged in finding.subject.values():
        assert tagged.source is not Provenance.INFERRED


def test_engine_emits_nothing_for_benign_same_identity() -> None:
    item = make_input(baseline_account="userA", replay_identity="userA")
    assert DetectionEngine().detect([item]) == ()


def test_engine_bfla(bfla_input: DetectionInput) -> None:
    (finding,) = DetectionEngine().detect([bfla_input])
    assert finding.owasp_class is OwaspClass.API5_BFLA


def test_engine_deduplicates_identical_inputs(
    bola_input: DetectionInput,
) -> None:
    findings = DetectionEngine().detect([bola_input, bola_input])
    assert len(findings) == 1


def test_finding_identity_is_deterministic_across_runs() -> None:
    first = DetectionEngine().detect([make_input()])
    second = DetectionEngine().detect([make_input()])
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert len(first) == 1


def test_engine_rule_order_is_stable() -> None:
    engine = DetectionEngine()
    ids = [r.rule_id for r in engine.rules]
    assert ids == sorted(ids)


def test_results_sorted_by_finding_id() -> None:
    # Two distinct findings (one BOLA, one BFLA) from two inputs.
    bola = make_input()
    bfla = make_input(
        baseline_status=403,
        baseline_body=b'{"error": "forbidden"}',
        replay_status=200,
        replay_body=b'{"ok": true}',
    )
    findings = DetectionEngine().detect([bfla, bola])
    ids = [f.finding_id for f in findings]
    assert ids == sorted(ids)
    assert len(findings) == 2
