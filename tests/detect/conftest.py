"""Shared builders for the detect test suite.

Assembles a coherent capture -> replay -> compare chain so detection runs
over genuine model artifacts (and the DetectionInput consistency checks pass).
"""

from __future__ import annotations

import pytest

from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.compare import ComparisonEngine
from charon.detect import DetectionInput
from charon.model import (
    CapturedExchange,
    HttpMessage,
    ReplayIdentity,
    ReplayRequest,
    ReplayResult,
)

_JSON = (("Content-Type", "application/json"),)


def make_baseline(
    *,
    account_label: str = "userA",
    status_code: int = 200,
    body: bytes | None = b'{"id": 8821, "owner": "userA"}',
) -> CapturedExchange:
    recorder = CaptureRecorder()
    return recorder.record(
        RawExchange(
            account_label=account_label,
            method="GET",
            url="https://api.example.test/api/invoices/8821",
            status_code=status_code,
            request=RawMessage(headers=_JSON),
            response=RawMessage(headers=_JSON, body=body),
        )
    )


def make_replay_request(
    baseline: CapturedExchange, *, identity_label: str = "userB"
) -> ReplayRequest:
    return ReplayRequest(
        source_exchange_id=baseline.exchange_id,
        identity=ReplayIdentity(label=identity_label),
        method=baseline.method,
        url=baseline.url,
        request=HttpMessage(headers=_JSON),
    )


def make_replay_result(
    baseline: CapturedExchange,
    request: ReplayRequest,
    *,
    status_code: int = 200,
    body: bytes | None = b'{"id": 8821, "owner": "userA"}',
) -> ReplayResult:
    return ReplayResult(
        replay_request_id=request.request_id,
        baseline_exchange_id=baseline.exchange_id,
        status_code=status_code,
        response=HttpMessage(headers=_JSON, body=body),
    )


def make_input(
    *,
    baseline_account: str = "userA",
    baseline_status: int = 200,
    baseline_body: bytes | None = b'{"id": 8821, "owner": "userA"}',
    replay_identity: str = "userB",
    replay_status: int = 200,
    replay_body: bytes | None = b'{"id": 8821, "owner": "userA"}',
) -> DetectionInput:
    """Build a full, consistent DetectionInput via the real engines."""
    baseline = make_baseline(
        account_label=baseline_account,
        status_code=baseline_status,
        body=baseline_body,
    )
    request = make_replay_request(baseline, identity_label=replay_identity)
    result = make_replay_result(
        baseline, request, status_code=replay_status, body=replay_body
    )
    comparison = ComparisonEngine().compare(baseline, result)
    return DetectionInput(
        comparison=comparison,
        baseline_exchange=baseline,
        replay_request=request,
        replay_result=result,
    )


@pytest.fixture
def bola_input() -> DetectionInput:
    # Cross-identity, granted -> granted, identical body.
    return make_input()


@pytest.fixture
def bfla_input() -> DetectionInput:
    # Cross-identity, denied -> granted.
    return make_input(
        baseline_status=403,
        baseline_body=b'{"error": "forbidden"}',
        replay_status=200,
        replay_body=b'{"ok": true}',
    )
