from __future__ import annotations

from charon.detect import MatrixAnalysis, RuleConfig
from charon.model import OwaspClass, Severity

from tests.detect.conftest import make_input


def test_widespread_privilege_fires_when_threshold_exceeded() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(baseline_account="userB", replay_identity="attacker"),
        make_input(baseline_account="userC", replay_identity="attacker"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "matrix.widespread-bola.privilege-escalation-web"
    assert f.owasp_class is OwaspClass.API1_BOLA


def test_widespread_privilege_does_not_fire_below_threshold() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(baseline_account="userB", replay_identity="attacker"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 0


def test_widespread_privilege_uses_only_granted_accesses() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(
            baseline_account="userB",
            replay_identity="attacker",
            replay_status=403,
            replay_body=b'{"error": "no"}',
        ),
        make_input(baseline_account="userC", replay_identity="attacker"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 0


def test_widespread_privilege_ignores_same_identity() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userA"),
        make_input(baseline_account="userB", replay_identity="attacker"),
        make_input(baseline_account="userC", replay_identity="attacker"),
        make_input(baseline_account="userD", replay_identity="attacker"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.subject["replay_identity"].value == "attacker"
    assert f.subject["accounts_accessed"].value == "3"


def test_widespread_privilege_configurable_threshold() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(baseline_account="userB", replay_identity="attacker"),
        make_input(baseline_account="userC", replay_identity="attacker"),
    )
    config = RuleConfig(widespread_bola_threshold=5)
    result = MatrixAnalysis(config=config).analyze(items)
    assert len(result.findings) == 0


def test_mutual_access_fires() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userB"),
        make_input(baseline_account="userB", replay_identity="userA"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "matrix.mutual-access.privilege-inversion"
    assert f.owasp_class is OwaspClass.INTERNAL_MISSING_AUTHZ
    assert f.severity is Severity.CRITICAL


def test_mutual_access_does_not_fire_without_cross_access() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userB"),
        make_input(baseline_account="userC", replay_identity="userA"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 0


def test_mutual_access_does_not_fire_same_identity() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userA"),
        make_input(baseline_account="userB", replay_identity="userB"),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 0


def test_matrix_respects_disable_flag() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="userB"),
        make_input(baseline_account="userB", replay_identity="userA"),
        make_input(baseline_account="userC", replay_identity="attacker"),
        make_input(baseline_account="userD", replay_identity="attacker"),
        make_input(baseline_account="userE", replay_identity="attacker"),
    )
    config = RuleConfig(enable_matrix=False)
    result = MatrixAnalysis(config=config).analyze(items)
    assert len(result.findings) == 0


def test_empty_items_produces_no_findings() -> None:
    result = MatrixAnalysis().analyze(())
    assert len(result.findings) == 0


def test_widespread_privilege_subject_contains_correct_fields() -> None:
    items = (
        make_input(baseline_account="userA", replay_identity="attacker"),
        make_input(baseline_account="userB", replay_identity="attacker"),
        make_input(baseline_account="userC", replay_identity="attacker"),
    )
    result = MatrixAnalysis().analyze(items)
    f = result.findings[0]
    assert f.subject["replay_identity"].value == "attacker"
    assert f.subject["accounts_accessed"].value == "3"


def test_mutual_access_subject_contains_identities() -> None:
    items = (
        make_input(baseline_account="alice", replay_identity="bob"),
        make_input(baseline_account="bob", replay_identity="alice"),
    )
    result = MatrixAnalysis().analyze(items)
    f = result.findings[0]
    assert f.subject["identity_a"].value == "alice"
    assert f.subject["identity_b"].value == "bob"


def test_widespread_privilege_groups_by_url() -> None:
    items = (
        make_input(
            baseline_account="userA",
            replay_identity="attacker",
            baseline_body=b'{"id": 1, "owner": "userA"}',
            replay_body=b'{"id": 1, "owner": "userA"}',
        ),
        make_input(
            baseline_account="userB",
            replay_identity="attacker",
            baseline_body=b'{"id": 2, "owner": "userB"}',
            replay_body=b'{"id": 2, "owner": "userB"}',
        ),
        make_input(
            baseline_account="userC",
            replay_identity="attacker",
            baseline_body=b'{"id": 3, "owner": "userC"}',
            replay_body=b'{"id": 3, "owner": "userC"}',
        ),
    )
    result = MatrixAnalysis().analyze(items)
    assert len(result.findings) == 1
