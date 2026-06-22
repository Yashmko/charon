"""Tests for the read-only report builder and traceability."""

from __future__ import annotations

from charon.model import Annotation, Provenanced
from charon.model.annotation import AnnotationKind
from charon.report import ReportBuilder, ReportMode

from tests.report.conftest import Chain, build_chain


def test_build_resolves_full_trace(chain: Chain) -> None:
    report = ReportBuilder(chain.index()).build([chain.finding])
    assert report.finding_count == 1
    fr = report.findings[0]
    assert fr.finding_id == chain.finding.finding_id
    assert chain.comparison.comparison_id in fr.trace.comparison_ids
    assert chain.baseline.exchange_id in fr.trace.captured_exchange_ids
    assert chain.request.request_id in fr.trace.replay_request_ids
    assert chain.result.result_id in fr.trace.replay_result_ids


def test_observed_and_derived_facts_are_separated(chain: Chain) -> None:
    fr = ReportBuilder(chain.index()).build([chain.finding]).findings[0]
    observed_sources = {f.source for f in fr.observed_facts}
    derived_sources = {f.source for f in fr.derived_facts}
    assert "derived" not in observed_sources
    assert derived_sources <= {"derived"}
    # Decisions are derived; account labels are observed/replayed.
    derived_names = {f.name for f in fr.derived_facts}
    assert "baseline_decision" in derived_names
    assert "replay_decision" in derived_names


def test_builder_does_not_mutate_finding(chain: Chain) -> None:
    before = chain.finding.finding_id
    severity_before = chain.finding.severity
    ReportBuilder(chain.index()).build([chain.finding])
    assert chain.finding.finding_id == before
    assert chain.finding.severity is severity_before


def test_title_and_summary_only_use_subject_fields(chain: Chain) -> None:
    fr = ReportBuilder(chain.index()).build([chain.finding]).findings[0]
    assert chain.finding.owasp_class.value in fr.title
    assert "GET" in fr.title
    assert chain.finding.rule_id in fr.summary


def test_deterministic_mode_strips_annotations(chain: Chain) -> None:
    annotation = Annotation(
        target_ref=chain.finding.finding_id,
        kind=AnnotationKind.SEMANTIC_LABEL,
        content=Provenanced.inferred("Invoice object"),
    )
    report = ReportBuilder(chain.index()).build(
        [chain.finding],
        mode=ReportMode.DETERMINISTIC,
        annotations=[annotation],
    )
    assert report.findings[0].annotations == ()


def test_enriched_mode_attaches_annotations(chain: Chain) -> None:
    annotation = Annotation(
        target_ref=chain.finding.finding_id,
        kind=AnnotationKind.SEMANTIC_LABEL,
        content=Provenanced.inferred("Invoice object"),
    )
    report = ReportBuilder(chain.index()).build(
        [chain.finding],
        mode=ReportMode.ENRICHED,
        annotations=[annotation],
    )
    annotations = report.findings[0].annotations
    assert len(annotations) == 1
    assert annotations[0].content == "Invoice object"


def test_missing_artifacts_degrade_gracefully(chain: Chain) -> None:
    # No index entries: trace still lists refs, field diffs are empty.
    report = ReportBuilder().build([chain.finding])
    fr = report.findings[0]
    assert fr.trace.comparison_ids  # refs come from the finding's evidence
    assert fr.field_differences == ()  # comparison could not be resolved


def test_findings_sorted_by_finding_id() -> None:
    a = build_chain(baseline_account="userA", replay_identity="userB")
    b = build_chain(baseline_account="userC", replay_identity="userD")
    report = ReportBuilder().build([b.finding, a.finding])
    ids = [f.finding_id for f in report.findings]
    assert ids == sorted(ids)
