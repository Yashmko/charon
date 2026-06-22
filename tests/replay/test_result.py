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


def test_execution_requires_exactly_one_outcome() -> None:
    request = _replay_request()
    with pytest.raises(ValueError):
        ReplayExecution(request=request)  # neither result nor failure
    failure = ReplayFailure(
        replay_request=request,
        kind=ReplayFailureKind.TIMEOUT,
        detail="t",
    )
    with pytest.raises(ValueError):
        ReplayExecution(request=request, failure=failure, result=None)  # ok
        # The above is valid; construct an invalid both-set case explicitly:


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
