from __future__ import annotations

from charon.detect import DetectionEngine, score_findings
from charon.detect.confidence import ConfidenceScorer
from charon.detect.rules import RuleConfig
from charon.model import Finding, Severity

from tests.detect.conftest import make_input


def test_missing_authz_has_high_confidence() -> None:
    items = (
        make_input(
            baseline_account="userA",
            replay_identity="userB",
            replay_status=200,
        ),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for finding in findings:
        if "missing-authz" in finding.rule_id:
            assert scores[finding.finding_id] == 0.9


def test_bola_has_default_confidence() -> None:
    items = (make_input(),)
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for finding in findings:
        if "bola" in finding.rule_id and "bopla" not in finding.rule_id and "widespread" not in finding.rule_id and "mutual" not in finding.rule_id:
            assert scores[finding.finding_id] == 0.5, f"Expected 0.5 for {finding.rule_id}, got {scores[finding.finding_id]}"


def test_bfla_has_default_confidence() -> None:
    items = (
        make_input(
            baseline_status=403,
            baseline_body=b'{"error": "forbidden"}',
            replay_status=200,
            replay_body=b'{"ok": true}',
        ),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for finding in findings:
        if "bfla" in finding.rule_id and "widespread" not in finding.rule_id and "mutual" not in finding.rule_id:
            assert scores[finding.finding_id] == 0.6


def test_multirule_bonus_increases_confidence() -> None:
    items = (
        make_input(
            baseline_account="userA",
            replay_identity="userB",
            baseline_body=b'{"id": 1, "owner": "userA", "email": "a@x.test", "role": "admin"}',
            replay_body=b'{"id": 1, "owner": "userA", "email": "a@x.test", "role": "admin"}',
        ),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    # BOLA + BOPLA both fire on this input -> 0.5 + 0.2 = 0.7
    # MissingAuthz also fires (no auth header) -> that's a 3rd rule.
    # So BOLA gets: 0.5 (base) + 0.2 (multirule bonus, since max_rules >= 2)
    for finding in findings:
        if "bola" in finding.rule_id and "bopla" not in finding.rule_id:
            assert scores[finding.finding_id] == 0.7


def test_widespread_matrix_has_high_confidence() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(baseline_account="userB", replay_identity="attacker"),
        make_input(baseline_account="userC", replay_identity="attacker"),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for finding in findings:
        if "widespread" in finding.rule_id:
            assert scores[finding.finding_id] == 0.8


def test_mutual_access_has_highest_confidence() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userB"),
        make_input(baseline_account="userB", replay_identity="userA"),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for finding in findings:
        if "mutual" in finding.rule_id:
            assert scores[finding.finding_id] == 0.9


def test_widespread_bonus_boosts_per_input_rules() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(baseline_account="userB", replay_identity="attacker"),
        make_input(baseline_account="userC", replay_identity="attacker"),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for finding in findings:
        if "bola" in finding.rule_id and "bopla" not in finding.rule_id and "widespread" not in finding.rule_id:
            # 0.5 (base) + 0.15 (widespread bonus) = 0.65
            assert scores[finding.finding_id] == 0.65


def test_confidence_capped_at_one() -> None:
    items = (
        make_input(
            baseline_account="userA",
            replay_identity="attacker",
            baseline_body=b'{"id": 1, "owner": "userA", "email": "a@x.test", "role": "admin"}',
            replay_body=b'{"id": 1, "owner": "userA", "email": "a@x.test", "role": "admin"}',
        ),
        make_input(
            baseline_account="userB",
            replay_identity="attacker",
            baseline_body=b'{"id": 2, "owner": "userB", "email": "b@x.test", "role": "user"}',
            replay_body=b'{"id": 2, "owner": "userB", "email": "b@x.test", "role": "user"}',
        ),
        make_input(
            baseline_account="userC",
            replay_identity="attacker",
            baseline_body=b'{"id": 3, "owner": "userC", "email": "c@x.test", "role": "mod"}',
            replay_body=b'{"id": 3, "owner": "userC", "email": "c@x.test", "role": "mod"}',
        ),
        make_input(
            baseline_account="userD",
            replay_identity="attacker",
            baseline_body=b'{"id": 4, "owner": "userD", "email": "d@x.test", "role": "admin"}',
            replay_body=b'{"id": 4, "owner": "userD", "email": "d@x.test", "role": "admin"}',
        ),
    )
    engine = DetectionEngine()
    findings = engine.detect(items)
    scores = score_findings(findings, items)
    for fid, score in scores.items():
        assert 0.0 <= score <= 1.0


def test_confidence_with_config_override() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userB"),
        make_input(baseline_account="userB", replay_identity="userA"),
    )
    config = RuleConfig()
    scores = score_findings(
        DetectionEngine().detect(items),
        items,
        config,
    )
    for finding_id, score in scores.items():
        assert 0.0 <= score <= 1.0
