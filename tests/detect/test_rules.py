"""Tests for the individual deterministic rules."""

from __future__ import annotations

from charon.detect import BflaRule, BolaRule, DetectionInput, RuleConfig
from charon.model import OwaspClass, Severity

from tests.detect.conftest import make_input


def test_bola_fires_on_cross_account_identical_grant(
    bola_input: DetectionInput,
) -> None:
    match = BolaRule().evaluate(bola_input)
    assert match is not None
    assert match.owasp_class is OwaspClass.API1_BOLA
    assert match.subject["baseline_account"].value == "userA"
    assert match.subject["replay_identity"].value == "userB"


def test_bola_does_not_fire_same_identity() -> None:
    item = make_input(baseline_account="userA", replay_identity="userA")
    assert BolaRule().evaluate(item) is None


def test_bola_does_not_fire_when_body_redacted() -> None:
    # Cross-account response differs -> redaction -> no clean exposure.
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test"}',
        replay_body=b'{"id": 8821, "owner": "userA"}',
    )
    assert BolaRule().evaluate(item) is None


def test_bola_does_not_fire_when_replay_denied() -> None:
    item = make_input(replay_status=403, replay_body=b'{"error": "no"}')
    assert BolaRule().evaluate(item) is None


def test_bola_respects_disable_flag(bola_input: DetectionInput) -> None:
    rule = BolaRule(RuleConfig(enable_bola=False))
    assert rule.evaluate(bola_input) is None


def test_bola_severity_is_configurable(bola_input: DetectionInput) -> None:
    rule = BolaRule(RuleConfig(bola_severity=Severity.CRITICAL))
    match = rule.evaluate(bola_input)
    assert match is not None
    assert match.severity is Severity.CRITICAL


def test_bfla_fires_on_denied_to_granted(bfla_input: DetectionInput) -> None:
    match = BflaRule().evaluate(bfla_input)
    assert match is not None
    assert match.owasp_class is OwaspClass.API5_BFLA


def test_bfla_does_not_fire_when_baseline_granted(
    bola_input: DetectionInput,
) -> None:
    # baseline granted -> not a denied->granted transition.
    assert BflaRule().evaluate(bola_input) is None


def test_bfla_does_not_fire_same_identity() -> None:
    item = make_input(
        baseline_account="userA",
        replay_identity="userA",
        baseline_status=403,
        baseline_body=b'{"error": "forbidden"}',
        replay_status=200,
        replay_body=b'{"ok": true}',
    )
    assert BflaRule().evaluate(item) is None


def test_bfla_does_not_fire_denied_stays_denied() -> None:
    item = make_input(
        baseline_status=403,
        baseline_body=b'{"error": "forbidden"}',
        replay_status=403,
        replay_body=b'{"error": "forbidden"}',
    )
    assert BflaRule().evaluate(item) is None
