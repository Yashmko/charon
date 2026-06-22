"""Deterministic JSON renderer.

Produces byte-for-byte identical output for identical inputs by sorting keys
and using fixed separators. Emits no Inferred content unless the report was
built in enriched mode (in which case annotations are clearly nested under a
separate ``annotations`` key).
"""

from __future__ import annotations

import json
from typing import Any

from charon.report.model import FindingReport, Report

__all__ = ["render_json"]


def _fact_list(facts: tuple[Any, ...]) -> list[dict[str, str]]:
    return [
        {"name": f.name, "value": f.value, "source": f.source} for f in facts
    ]


def _finding_dict(finding: FindingReport) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "owasp_class": finding.owasp_class,
        "severity": finding.severity,
        "title": finding.title,
        "summary": finding.summary,
        "observed_facts": _fact_list(finding.observed_facts),
        "derived_facts": _fact_list(finding.derived_facts),
        "field_differences": [
            {
                "location": d.location,
                "baseline_value": d.baseline_value,
                "other_value": d.other_value,
            }
            for d in finding.field_differences
        ],
        "trace": {
            "evidence_ids": list(finding.trace.evidence_ids),
            "comparison_ids": list(finding.trace.comparison_ids),
            "replay_request_ids": list(finding.trace.replay_request_ids),
            "replay_result_ids": list(finding.trace.replay_result_ids),
            "captured_exchange_ids": list(finding.trace.captured_exchange_ids),
        },
    }
    if finding.annotations:
        data["annotations"] = [
            {
                "target_ref": a.target_ref,
                "kind": a.kind,
                "content": a.content,
                "disagrees_with_evidence": a.disagrees_with_evidence,
            }
            for a in finding.annotations
        ]
    return data


def render_json(report: Report) -> str:
    """Render ``report`` as a deterministic JSON string."""
    payload = {
        "schema_version": report.schema_version,
        "mode": report.mode.value,
        "finding_count": report.finding_count,
        "findings": [_finding_dict(f) for f in report.findings],
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
