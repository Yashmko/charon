from __future__ import annotations

import json
import runpy
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_historical_summary_uses_revised_ground_truth_and_internal_class() -> None:
    runner: dict[str, Any] = runpy.run_path(
        str(REPO_ROOT / "docs/evaluation/run_eval.py")
    )
    ground_truth = json.loads(
        (REPO_ROOT / "docs/evaluation/ground_truth.json").read_text(
            encoding="utf-8"
        )
    )
    report = json.loads(
        (REPO_ROOT / "docs/evaluation/raw/charon-report.json").read_text(
            encoding="utf-8"
        )
    )
    previous_summary = json.loads(
        (REPO_ROOT / "docs/evaluation/raw/run-summary.json").read_text(
            encoding="utf-8"
        )
    )

    summary = runner["_summarize"](
        ground_truth, report, previous_summary["baseline_observations"]
    )

    assert summary["tested_case_count"] == 8
    assert summary["metric_case_count"] == 5
    assert summary["inconclusive_case_count"] == 3
    user_list = next(
        case for case in summary["case_results"]
        if case["case_id"] == "users-list-public"
    )
    assert user_list["expected_result"] == "inconclusive"
    assert user_list["included_in_metrics"] is False
    assert "API7" not in user_list["observed_classes"]
    assert "internal:missing-authorization" in user_list["observed_classes"]

    metrics = {
        metric["classification"]: metric for metric in summary["metrics"]
    }
    internal = metrics["internal:missing-authorization"]
    assert internal["classification_scope"] == "internal"
    assert internal["false_positives"] == 1
    assert internal["true_negatives"] == 4
    assert "owasp_class" not in internal
    assert metrics["API1"]["false_positives"] == 1
    assert metrics["API3"]["true_negatives"] == 3

    current_schema_report = json.loads(json.dumps(report))
    for finding in current_schema_report["findings"]:
        if finding["rule_id"] == "authz.missing-authz.no-authorization-header":
            finding.pop("owasp_class", None)
            finding["classification"] = "INTERNAL-MISSING-AUTHORIZATION"
            finding["classification_scope"] = "internal"
    current_summary = runner["_summarize"](
        ground_truth, current_schema_report, previous_summary["baseline_observations"]
    )
    current_internal = next(
        metric
        for metric in current_summary["metrics"]
        if metric["classification"] == "internal:missing-authorization"
    )
    assert current_internal["false_positives"] == 1
    assert any(
        finding["reported_code"] == "INTERNAL-MISSING-AUTHORIZATION"
        for finding in current_summary["observed_findings"]
        if finding["classification_scope"] == "internal"
    )


def test_policy_summary_normalizes_suppressed_legacy_api7() -> None:
    runner: dict[str, Any] = runpy.run_path(
        str(REPO_ROOT / "docs/evaluation/run_eval.py")
    )
    ground_truth = json.loads(
        (REPO_ROOT / "docs/evaluation/ground_truth.json").read_text(
            encoding="utf-8"
        )
    )
    directory = REPO_ROOT / "docs/evaluation/raw/part2-with-policy"
    report = json.loads((directory / "charon-report.json").read_text(encoding="utf-8"))
    previous_summary = json.loads(
        (directory / "run-summary.json").read_text(encoding="utf-8")
    )

    summary = runner["_summarize"](
        ground_truth, report, previous_summary["baseline_observations"]
    )

    assert summary["metric_case_count"] == 5
    assert summary["inconclusive_case_count"] == 3
    declaration = next(
        item for item in summary["policy_declarations"] if item["path"] == "/users/v1"
    )
    suppressed_internal = [
        finding
        for finding in declaration["suppressed_findings"]
        if finding["classification_scope"] == "internal"
    ]
    assert len(suppressed_internal) == 2
    assert all(
        finding["classification"] == "internal:missing-authorization"
        and finding["reported_code"] == "API7"
        for finding in suppressed_internal
    )
    assert all("owasp_class" not in finding for finding in suppressed_internal)
