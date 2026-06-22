"""Tests for the deterministic JSON and Markdown renderers."""

from __future__ import annotations

import json

from charon.report import (
    ReportBuilder,
    ReportMode,
    render_json,
    render_markdown,
)

from tests.report.conftest import Chain, build_chain


def test_json_is_byte_for_byte_deterministic(chain: Chain) -> None:
    report = ReportBuilder(chain.index()).build([chain.finding])
    assert render_json(report) == render_json(report)


def test_markdown_is_byte_for_byte_deterministic(chain: Chain) -> None:
    report = ReportBuilder(chain.index()).build([chain.finding])
    assert render_markdown(report) == render_markdown(report)


def test_json_is_valid_and_contains_core_fields(chain: Chain) -> None:
    report = ReportBuilder(chain.index()).build([chain.finding])
    data = json.loads(render_json(report))
    assert data["finding_count"] == 1
    assert data["mode"] == "deterministic"
    finding = data["findings"][0]
    assert finding["finding_id"] == chain.finding.finding_id
    assert finding["rule_id"] == chain.finding.rule_id
    assert finding["owasp_class"] == chain.finding.owasp_class.value
    assert finding["severity"] == chain.finding.severity.value
    assert finding["trace"]["comparison_ids"]


def test_markdown_contains_core_sections(chain: Chain) -> None:
    report = ReportBuilder(chain.index()).build([chain.finding])
    md = render_markdown(report)
    assert "# Charon Authorization Report" in md
    assert "### Observed facts" in md
    assert "### Derived deterministic conclusions" in md
    assert "### Traceability" in md
    assert chain.finding.finding_id in md


def test_empty_report_renders_cleanly() -> None:
    report = ReportBuilder().build([])
    md = render_markdown(report)
    js = json.loads(render_json(report))
    assert "_No findings._" in md
    assert js["finding_count"] == 0
    assert js["findings"] == []


def test_multiple_findings_are_ordered_and_stable() -> None:
    a = build_chain(baseline_account="userA", replay_identity="userB")
    b = build_chain(baseline_account="userC", replay_identity="userD")
    report1 = ReportBuilder().build([a.finding, b.finding])
    report2 = ReportBuilder().build([b.finding, a.finding])
    # Output is independent of input order.
    assert render_json(report1) == render_json(report2)
    assert render_markdown(report1) == render_markdown(report2)


def test_deterministic_mode_json_has_no_annotations(chain: Chain) -> None:
    from charon.model import Annotation, Provenanced
    from charon.model.annotation import AnnotationKind

    annotation = Annotation(
        target_ref=chain.finding.finding_id,
        kind=AnnotationKind.EXPLANATION,
        content=Provenanced.inferred("advisory text"),
    )
    report = ReportBuilder(chain.index()).build(
        [chain.finding],
        mode=ReportMode.DETERMINISTIC,
        annotations=[annotation],
    )
    assert "advisory text" not in render_json(report)
    assert "advisory text" not in render_markdown(report)
