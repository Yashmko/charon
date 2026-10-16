"""Tests for the deterministic JSON and Markdown renderers."""

from __future__ import annotations

import json

from charon.report import (
    PolicyDeclarationView,
    ReportBuilder,
    ReportMode,
    SuppressedFindingView,
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
    assert finding["classification_scope"] == (
        "owasp-api-security-top-10-2023"
    )
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


def test_internal_classification_is_not_rendered_as_an_owasp_category(
    chain: Chain,
) -> None:
    from dataclasses import replace

    from charon.model import OwaspClass

    internal_finding = replace(
        chain.finding, owasp_class=OwaspClass.INTERNAL_MISSING_AUTHZ
    )
    report = ReportBuilder(chain.index()).build([internal_finding])

    finding = json.loads(render_json(report))["findings"][0]
    assert finding["classification"] == "INTERNAL-MISSING-AUTHORIZATION"
    assert finding["classification_scope"] == "internal"
    assert "owasp_class" not in finding
    markdown = render_markdown(report)
    assert "internal Charon heuristic; not an OWASP category" in markdown
    assert "**OWASP:** API7" not in markdown


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


def test_empty_report_without_policy_keeps_legacy_shape() -> None:
    report = ReportBuilder().build([])
    data = json.loads(render_json(report))

    assert "policy_declarations" not in data
    assert "Policy-declared endpoints" not in render_markdown(report)


def test_policy_declaration_is_reported_separately_from_findings() -> None:
    declaration = PolicyDeclarationView(
        method="GET",
        path="/status",
        policy_path="/status",
        access="public",
        allowed_roles=(),
        matched_exchange_ids=("sha256:exchange",),
        suppressed_findings=(
            SuppressedFindingView(
                finding_id="sha256:suppressed",
                rule_id="authz.bola.cross-account-object-exposure",
                classification="API1",
                classification_scope="owasp-api-security-top-10-2023",
            ),
        ),
    )
    report = ReportBuilder().build([], policy_declarations=(declaration,))

    data = json.loads(render_json(report))
    assert data["finding_count"] == 0
    assert data["findings"] == []
    assert data["policy_declarations"][0]["status"] == "policy-declared"
    suppressed = data["policy_declarations"][0]["suppressed_findings"][0]
    assert suppressed["rule_id"] == "authz.bola.cross-account-object-exposure"
    assert suppressed["classification"] == "API1"
    assert suppressed["classification_scope"] == "owasp-api-security-top-10-2023"
    assert suppressed["owasp_class"] == "API1"
    markdown = render_markdown(report)
    assert "Policy-declared endpoints" in markdown
    assert "`policy-declared`" in markdown
    assert "_No findings._" in markdown


def test_internal_suppressed_classification_has_no_owasp_field() -> None:
    declaration = PolicyDeclarationView(
        method="GET",
        path="/users/v1",
        policy_path="/users/v1",
        access="public",
        allowed_roles=(),
        matched_exchange_ids=("sha256:exchange",),
        suppressed_findings=(
            SuppressedFindingView(
                finding_id="sha256:suppressed",
                rule_id="authz.missing-authz.no-authorization-header",
                classification="INTERNAL-MISSING-AUTHORIZATION",
                classification_scope="internal",
            ),
        ),
    )
    report = ReportBuilder().build([], policy_declarations=(declaration,))

    suppressed = json.loads(render_json(report))["policy_declarations"][0][
        "suppressed_findings"
    ][0]
    assert suppressed["classification_scope"] == "internal"
    assert suppressed["classification"] == "INTERNAL-MISSING-AUTHORIZATION"
    assert "owasp_class" not in suppressed
    assert "internal Charon heuristic; not an OWASP category" in render_markdown(
        report
    )


def test_policy_declarations_are_stable_in_both_report_modes() -> None:
    declaration = PolicyDeclarationView(
        method="GET",
        path="/status",
        policy_path="/status",
        access="public",
        allowed_roles=(),
        matched_exchange_ids=(),
        suppressed_findings=(),
    )
    for mode in (ReportMode.DETERMINISTIC, ReportMode.ENRICHED):
        report = ReportBuilder().build([], mode=mode, policy_declarations=[declaration])
        assert render_json(report) == render_json(report)
        assert render_markdown(report) == render_markdown(report)
        assert "policy-declared" in render_json(report)
        assert "policy-declared" in render_markdown(report)
