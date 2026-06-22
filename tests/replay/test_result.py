"""Tests for the ReplayExecution / ReplayFailure outcome types."""

from __future__ import annotations

import pytest

from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.model import ReplayRequest
from charon.replay import (
    ReplayCredential,
    ReplayEngine,
    ReplayFailure,
    ReplayFailureKind,
)
from charon.replay.result import ReplayExecution

from tests.replay.conftest import StubTransport


def _replay_request() -> ReplayRequest:
    recorder = CaptureRecorder()
    exchange = recorder.record(
        RawExchange(
            account_label="userA",
            method="GET",
            url="https://h.test/x/1",
            status_code=200,
            request=RawMessage(),
        )
    )
    engine = ReplayEngine(StubTransport())
    return engine.build_request(exchange, ReplayCredential(label="userB"))


def test_execution_rejects_no_outcome() -> None:
    request = _replay_request()
    with pytest.raises(ValueError):
        ReplayExecution(request=request)  # neither result nor failure


def test_execution_rejects_both_outcomes() -> None:
    request = _replay_request()
    failure = ReplayFailure(
        replay_request=request,
        kind=ReplayFailureKind.TIMEOUT,
        detail="t",
    )
    result = request  # any non-None placeholder for the result slot
    with pytest.raises(ValueError):
        ReplayExecution(
            request=request,
            failure=failure,
            result=result,  # type: ignore[arg-type]
        )


def test_execution_accepts_failure_only() -> None:
    request = _replay_request()
    failure = ReplayFailure(
        replay_request=request,
        kind=ReplayFailureKind.TIMEOUT,
        detail="t",
    )
    execution = ReplayExecution(request=request, failure=failure)
    assert not execution.succeeded


def test_failure_record_is_not_successful() -> None:
    request = _replay_request()
    failure = ReplayFailure(
        replay_request=request,
        kind=ReplayFailureKind.CONNECTION,
        detail="refused",
    )
    assert not failure.succeeded
    execution = ReplayExecution(request=request, failure=failure)
    assert not execution.succeeded
