"""Tests for the ReplayEngine: success, failure, determinism, secrets."""

from __future__ import annotations

import pytest
from charon.model import CapturedExchange, Provenance, ReplayRequest, ReplayResult
from charon.replay import (
    ReplayCredential,
    ReplayEngine,
    ReplayFailureKind,
    TransportRequest,
    TransportResponse,
)
from charon.replay.credential import REDACTED_PLACEHOLDER
from charon.replay.errors import (
    ReplayConnectionError,
    ReplayMalformedResponseError,
    ReplayTimeoutError,
    ReplayTransportError,
)

from tests.replay.conftest import StubTransport


def test_successful_replay_produces_replayed_result(
    exchange: CapturedExchange,
) -> None:
    transport = StubTransport(
        TransportResponse(status_code=200, body=b'{"id":8821}')
    )
    engine = ReplayEngine(transport)
    execution = engine.replay(exchange, ReplayCredential(label="userB"))

    assert execution.succeeded
    assert isinstance(execution.request, ReplayRequest)
    assert isinstance(execution.result, ReplayResult)
    assert execution.result.provenance is Provenance.REPLAYED
    assert execution.result.status_code == 200
    assert execution.result.response.body == b'{"id":8821}'
    assert execution.result.replay_request_id == execution.request.request_id
    assert execution.result.baseline_exchange_id == exchange.exchange_id


def test_request_references_source_exchange(exchange: CapturedExchange) -> None:
    engine = ReplayEngine(StubTransport())
    execution = engine.replay(exchange, ReplayCredential(label="userB"))
    assert execution.request.source_exchange_id == exchange.exchange_id
    assert execution.request.identity.label == "userB"


def test_auth_substitution_applied_to_outgoing_request(
    exchange: CapturedExchange,
) -> None:
    transport = StubTransport()
    engine = ReplayEngine(transport)
    engine.replay(exchange, ReplayCredential(label="userB", bearer_token="userB-tok"))

    assert transport.last_request is not None
    sent = dict(transport.last_request.headers)
    # The outgoing (transient) request carries the real swapped credential.
    assert sent["authorization"] == "Bearer userB-tok"
    # Unrelated structure is preserved.
    assert sent["accept"] == "*/*"


def test_secrets_never_persisted_in_replay_request(
    exchange: CapturedExchange,
) -> None:
    engine = ReplayEngine(StubTransport())
    execution = engine.replay(
        exchange, ReplayCredential(label="userB", bearer_token="userB-tok")
    )
    persisted = dict(execution.request.request.headers)
    assert persisted["authorization"] == REDACTED_PLACEHOLDER
    # No secret value appears anywhere in the addressed content.
    assert "userB-tok" not in str(execution.request.to_canonical())
    assert "userA-secret" not in str(execution.request.to_canonical())


def test_cookie_replacement(exchange: CapturedExchange) -> None:
    transport = StubTransport()
    engine = ReplayEngine(transport)
    engine.replay(
        exchange,
        ReplayCredential(label="userB", cookies=(("sid", "new"),)),
    )
    assert transport.last_request is not None
    assert dict(transport.last_request.headers)["cookie"] == "sid=new"


def test_binary_payload_preserved(exchange: CapturedExchange) -> None:
    raw = b"\x89PNG\r\n\x1a\n\xff\x00"
    transport = StubTransport(TransportResponse(status_code=200, body=raw))
    engine = ReplayEngine(transport)
    execution = engine.replay(exchange, ReplayCredential(label="userB"))
    assert execution.result is not None
    assert execution.result.response.body == raw


def test_replay_is_deterministic(exchange: CapturedExchange) -> None:
    def run() -> ReplayResult:
        transport = StubTransport(
            TransportResponse(status_code=200, body=b"same")
        )
        engine = ReplayEngine(transport)
        execution = engine.replay(
            exchange, ReplayCredential(label="userB", bearer_token="t")
        )
        assert execution.result is not None
        return execution.result

    first = run()
    second = run()
    assert first.replay_request_id == second.replay_request_id
    assert first.result_id == second.result_id


def test_redirects_recorded_as_nondeterminism_notes(
    exchange: CapturedExchange,
) -> None:
    transport = StubTransport(
        TransportResponse(
            status_code=200,
            redirect_chain=("https://api.example.test/old",),
        )
    )
    engine = ReplayEngine(transport, follow_redirects=True)
    execution = engine.replay(exchange, ReplayCredential(label="userB"))
    assert execution.result is not None
    assert execution.result.has_observed_nondeterminism
    assert any(
        "redirect-chain" in note
        for note in execution.result.nondeterminism_notes
    )


@pytest.mark.parametrize(
    ("error", "expected_kind"),
    [
        (ReplayTimeoutError("t"), ReplayFailureKind.TIMEOUT),
        (ReplayConnectionError("c"), ReplayFailureKind.CONNECTION),
        (ReplayMalformedResponseError("m"), ReplayFailureKind.MALFORMED_RESPONSE),
        (ReplayTransportError("x"), ReplayFailureKind.TRANSPORT),
    ],
)
def test_transport_failures_recorded_without_corrupting_evidence(
    exchange: CapturedExchange,
    error: Exception,
    expected_kind: ReplayFailureKind,
) -> None:
    def handler(_: TransportRequest) -> TransportResponse:
        raise error

    engine = ReplayEngine(StubTransport(handler=handler))
    execution = engine.replay(exchange, ReplayCredential(label="userB"))

    assert not execution.succeeded
    assert execution.result is None
    assert execution.failure is not None
    assert execution.failure.kind is expected_kind
    # The request artifact is still intact and traceable.
    assert execution.failure.replay_request is execution.request


def test_failure_does_not_raise(exchange: CapturedExchange) -> None:
    def handler(_: TransportRequest) -> TransportResponse:
        raise ReplayTimeoutError("boom")

    engine = ReplayEngine(StubTransport(handler=handler))
    # Should not raise; failure is captured.
    execution = engine.replay(exchange, ReplayCredential(label="userB"))
    assert execution.failure is not None
