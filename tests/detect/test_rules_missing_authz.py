from __future__ import annotations

from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.compare import ComparisonEngine
from charon.detect import DetectionInput, MissingAuthzRule, RuleConfig
from charon.model import (
    HttpMessage,
    OwaspClass,
    ReplayIdentity,
    ReplayRequest,
    ReplayResult,
    Severity,
)

from tests.detect.conftest import make_input


def _make_no_auth_input() -> DetectionInput:
    """Build an input with no Authorization header on the baseline request."""
    recorder = CaptureRecorder()
    baseline = recorder.record(
        RawExchange(
            account_label="userA",
            method="GET",
            url="https://api.example.test/api/invoices/8821",
            status_code=200,
            request=RawMessage(headers=(("Content-Type", "application/json"),)),
            response=RawMessage(
                headers=(("Content-Type", "application/json"),),
                body=b'{"id": 8821, "owner": "userA"}',
            ),
        )
    )
    request = ReplayRequest(
        source_exchange_id=baseline.exchange_id,
        identity=ReplayIdentity(label="userB"),
        method=baseline.method,
        url=baseline.url,
        request=HttpMessage(headers=(("Content-Type", "application/json"),)),
    )
    result = ReplayResult(
        replay_request_id=request.request_id,
        baseline_exchange_id=baseline.exchange_id,
        status_code=200,
        response=HttpMessage(
            headers=(("Content-Type", "application/json"),),
            body=b'{"id": 8821, "owner": "userA"}',
        ),
    )
    comparison = ComparisonEngine().compare(baseline, result)
    return DetectionInput(
        comparison=comparison,
        baseline_exchange=baseline,
        replay_request=request,
        replay_result=result,
    )


def test_missing_authz_fires_on_no_auth_header() -> None:
    item = _make_no_auth_input()
    assert MissingAuthzRule().evaluate(item) is not None


def test_missing_authz_rule_id() -> None:
    item = _make_no_auth_input()
    match = MissingAuthzRule().evaluate(item)
    assert match is not None
    assert match.rule_id == "authz.missing-authz.no-authorization-header"


def test_missing_authz_owasp_class() -> None:
    item = _make_no_auth_input()
    match = MissingAuthzRule().evaluate(item)
    assert match is not None
    assert match.owasp_class is OwaspClass.API7_MISSING_AUTHZ


def test_missing_authz_does_not_fire_same_identity() -> None:
    item = make_input(baseline_account="userA", replay_identity="userA")
    assert MissingAuthzRule().evaluate(item) is None


def test_missing_authz_does_not_fire_when_replay_denied() -> None:
    item = make_input(replay_status=403, replay_body=b'{"error": "no"}')
    assert MissingAuthzRule().evaluate(item) is None


def test_missing_authz_does_not_fire_when_auth_header_present() -> None:
    recorder = CaptureRecorder()
    baseline = recorder.record(
        RawExchange(
            account_label="userA",
            method="GET",
            url="https://api.example.test/api/invoices/8821",
            status_code=200,
            request=RawMessage(
                headers=(
                    ("Content-Type", "application/json"),
                    ("Authorization", "Bearer test-token"),
                ),
            ),
            response=RawMessage(
                headers=(("Content-Type", "application/json"),),
                body=b'{"id": 8821, "owner": "userA"}',
            ),
        )
    )
    request = ReplayRequest(
        source_exchange_id=baseline.exchange_id,
        identity=ReplayIdentity(label="userB"),
        method=baseline.method,
        url=baseline.url,
        request=HttpMessage(headers=(("Content-Type", "application/json"),)),
    )
    result = ReplayResult(
        replay_request_id=request.request_id,
        baseline_exchange_id=baseline.exchange_id,
        status_code=200,
        response=HttpMessage(
            headers=(("Content-Type", "application/json"),),
            body=b'{"id": 8821, "owner": "userA"}',
        ),
    )
    comparison = ComparisonEngine().compare(baseline, result)
    item = DetectionInput(
        comparison=comparison,
        baseline_exchange=baseline,
        replay_request=request,
        replay_result=result,
    )
    assert MissingAuthzRule().evaluate(item) is None


def test_missing_authz_respects_disable_flag() -> None:
    item = _make_no_auth_input()
    rule = MissingAuthzRule(RuleConfig(enable_missing_authz=False))
    assert rule.evaluate(item) is None


def test_missing_authz_severity_is_configurable() -> None:
    item = _make_no_auth_input()
    rule = MissingAuthzRule(RuleConfig(missing_authz_severity=Severity.HIGH))
    match = rule.evaluate(item)
    assert match is not None
    assert match.severity is Severity.HIGH


def test_missing_authz_fires_on_proxy_auth_header() -> None:
    recorder = CaptureRecorder()
    baseline = recorder.record(
        RawExchange(
            account_label="userA",
            method="GET",
            url="https://api.example.test/api/invoices/8821",
            status_code=200,
            request=RawMessage(
                headers=(
                    ("Content-Type", "application/json"),
                    ("Proxy-Authorization", "Basic dGVzdDp0ZXN0"),
                ),
            ),
            response=RawMessage(
                headers=(("Content-Type", "application/json"),),
                body=b'{"id": 8821, "owner": "userA"}',
            ),
        )
    )
    request = ReplayRequest(
        source_exchange_id=baseline.exchange_id,
        identity=ReplayIdentity(label="userB"),
        method=baseline.method,
        url=baseline.url,
        request=HttpMessage(headers=(("Content-Type", "application/json"),)),
    )
    result = ReplayResult(
        replay_request_id=request.request_id,
        baseline_exchange_id=baseline.exchange_id,
        status_code=200,
        response=HttpMessage(
            headers=(("Content-Type", "application/json"),),
            body=b'{"id": 8821, "owner": "userA"}',
        ),
    )
    comparison = ComparisonEngine().compare(baseline, result)
    item = DetectionInput(
        comparison=comparison,
        baseline_exchange=baseline,
        replay_request=request,
        replay_result=result,
    )
    assert MissingAuthzRule().evaluate(item) is None
