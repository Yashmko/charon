"""Deterministic Markdown renderer.

Produces a professional, byte-for-byte deterministic Markdown report. The
layout clearly separates observed facts, derived deterministic conclusions,
the triggering field differences, and the traceability references. Advisory
annotations (enriched mode only) are rendered in a clearly-labeled,
separate section.
"""

from __future__ import annotations

from charon.report.model import FindingReport, ProvenancedFact, Report

__all__ = ["render_markdown"]


def _facts_table(facts: tuple[ProvenancedFact, ...]) -> list[str]:
    if not facts:
        return ["_None._"]
    lines = ["| Field | Value | Source |", "| --- | --- | --- |"]
    for fact in facts:
        lines.append(f"| {fact.name} | {fact.value} | {fact.source} |")
    return lines


def _trace_lines(finding: FindingReport) -> list[str]:
    trace = finding.trace
    sections = [
        ("Evidence", trace.evidence_ids),
        ("Comparison", trace.comparison_ids),
        ("Replay request", trace.replay_request_ids),
        ("Replay result", trace.replay_result_ids),
        ("Captured exchange", trace.captured_exchange_ids),
    ]
    lines: list[str] = []
    for label, refs in sections:
        rendered = ", ".join(f"`{ref}`" for ref in refs) if refs else "_none_"
        lines.append(f"- **{label}:** {rendered}")
    return lines


def _field_diff_lines(finding: FindingReport) -> list[str]:
    if not finding.field_differences:
        return ["_No field differences recorded._"]
    lines = [
        "| Location | Baseline | Replay |",
        "| --- | --- | --- |",
    ]
    for diff in finding.field_differences:
        baseline = "_(absent)_" if diff.baseline_value is None else diff.baseline_value
        other = "_(absent)_" if diff.other_value is None else diff.other_value
        lines.append(f"| {diff.location} | {baseline} | {other} |")
    return lines


def _finding_section(finding: FindingReport) -> list[str]:
    lines = [
        f"## {finding.title}",
        "",
        f"- **Finding ID:** `{finding.finding_id}`",
        f"- **Rule:** `{finding.rule_id}`",
        f"- **OWASP:** {finding.owasp_class}",
        f"- **Severity:** {finding.severity}",
        "",
        "### Summary",
        "",
        finding.summary,
        "",
        "### Observed facts",
        "",
        *_facts_table(finding.observed_facts),
        "",
        "### Derived deterministic conclusions",
        "",
        *_facts_table(finding.derived_facts),
        "",
        "### Triggering field differences",
        "",
        *_field_diff_lines(finding),
        "",
        "### Traceability",
        "",
        *_trace_lines(finding),
    ]
    if finding.annotations:
        lines.extend(
            [
                "",
                "### Advisory annotations (inferred, non-authoritative)",
                "",
            ]
        )
        for annotation in finding.annotations:
            flag = (
                " (disagrees with evidence)"
                if annotation.disagrees_with_evidence
                else ""
            )
            lines.append(
                f"- _{annotation.kind}{flag}:_ {annotation.content}"
            )
    return lines


def render_markdown(report: Report) -> str:
    """Render ``report`` as a deterministic Markdown string."""
    lines = [
        "# Charon Authorization Report",
        "",
        f"- **Mode:** {report.mode.value}",
        f"- **Schema version:** {report.schema_version}",
        f"- **Findings:** {report.finding_count}",
        "",
    ]
    if not report.findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    for finding in report.findings:
        lines.extend(_finding_section(finding))
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"
