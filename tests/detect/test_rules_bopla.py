from __future__ import annotations

from charon.detect import BoplaRule, DetectionInput, RuleConfig
from charon.model import OwaspClass, Severity

from tests.detect.conftest import make_input


def test_bopla_fires_on_cross_account_rich_body() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
        replay_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
    )
    match = BoplaRule().evaluate(item)
    assert match is not None
    assert match.owasp_class is OwaspClass.API3_BOPLA
    assert match.subject["body_field_count"].value == "3"
    assert match.subject["baseline_account"].value == "userA"
    assert match.subject["replay_identity"].value == "userB"


def test_bopla_does_not_fire_same_identity() -> None:
    item = make_input(
        baseline_account="userA",
        replay_identity="userA",
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test"}',
        replay_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test"}',
    )
    assert BoplaRule().evaluate(item) is None


def test_bopla_does_not_fire_when_replay_denied() -> None:
    item = make_input(
        replay_status=403,
        replay_body=b'{"error": "forbidden"}',
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test"}',
    )
    assert BoplaRule().evaluate(item) is None


def test_bopla_does_not_fire_when_body_differs() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
        replay_body=b'{"id": 8821, "owner": "userA"}',
    )
    assert BoplaRule().evaluate(item) is None


def test_bopla_does_not_fire_on_identifier_only_body() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA"}',
        replay_body=b'{"id": 8821, "owner": "userA"}',
    )
    assert BoplaRule().evaluate(item) is None


def test_bopla_does_not_fire_on_body_below_threshold() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "email": "a@x.test"}',
        replay_body=b'{"id": 8821, "email": "a@x.test"}',
    )
    assert BoplaRule().evaluate(item) is None


def test_bopla_respects_disable_flag() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
        replay_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
    )
    rule = BoplaRule(RuleConfig(enable_bopla=False))
    assert rule.evaluate(item) is None


def test_bopla_severity_is_configurable() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
        replay_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test", "role": "admin"}',
    )
    rule = BoplaRule(RuleConfig(bopla_severity=Severity.CRITICAL))
    match = rule.evaluate(item)
    assert match is not None
    assert match.severity is Severity.CRITICAL


def test_bopla_configurable_min_data_fields() -> None:
    item = make_input(
        baseline_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test"}',
        replay_body=b'{"id": 8821, "owner": "userA", "email": "a@x.test"}',
    )
    rule = BoplaRule(RuleConfig(bopla_min_data_fields=1))
    match = rule.evaluate(item)
    assert match is not None
    assert match.subject["body_field_count"].value == "2"


def test_bopla_does_not_fire_on_empty_body() -> None:
    item = make_input(baseline_body=None, replay_body=None)
    assert BoplaRule().evaluate(item) is None
