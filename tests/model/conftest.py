"""Shared fixtures/builders for the model test suite.

These builders assemble a full, valid audit chain
(Finding -> Evidence -> Comparison -> Replay/Captured) so individual tests can
focus on the behavior under test rather than on construction boilerplate.
"""

from __future__ import annotations

import pytest

from charon.model import (
    AccessDecision,
    CapturedExchange,
    Comparison,
    Evidence,
    HttpMessage,
    ReplayIdentity,
    ReplayRequest,
    ReplayResult,
    ResponseSnapshot,
)


@pytest.fixture
def captured_exchange() -> CapturedExchange:
    return CapturedExchange(
        account_label="userA",
        method="get",
        url="https://example.test/api/invoices/8821",
        request=HttpMessage(headers=(("Authorization", "Bearer a"),)),
        status_code=200,
        response=HttpMessage(body='{"id":8821,"owner_id":"userA"}'),
        resource_refs=(("path", "id", "8821"),),
    )


@pytest.fixture
def replay_request(captured_exchange: CapturedExchange) -> ReplayRequest:
    return ReplayRequest(
        source_exchange_id=captured_exchange.exchange_id,
        identity=ReplayIdentity(label="userB"),
        method="GET",
        url="https://example.test/api/invoices/8821",
        request=HttpMessage(headers=(("Authorization", "Bearer b"),)),
    )


@pytest.fixture
def replay_result(
    replay_request: ReplayRequest, captured_exchange: CapturedExchange
) -> ReplayResult:
    return ReplayResult(
        replay_request_id=replay_request.request_id,
        baseline_exchange_id=captured_exchange.exchange_id,
        status_code=200,
        response=HttpMessage(body='{"id":8821,"owner_id":"userA"}'),
    )


@pytest.fixture
def comparison(
    captured_exchange: CapturedExchange, replay_result: ReplayResult
) -> Comparison:
    return Comparison(
        baseline_ref=captured_exchange.exchange_id,
        other_ref=replay_result.result_id,
        baseline=ResponseSnapshot(200, AccessDecision.GRANTED),
        other=ResponseSnapshot(200, AccessDecision.GRANTED),
    )


@pytest.fixture
def evidence(
    comparison: Comparison,
    captured_exchange: CapturedExchange,
    replay_request: ReplayRequest,
    replay_result: ReplayResult,
) -> Evidence:
    return Evidence(
        comparison_ref=comparison.comparison_id,
        captured_exchange_refs=(captured_exchange.exchange_id,),
        replay_pairs=((replay_request.request_id, replay_result.result_id),),
    )
