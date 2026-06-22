"""Shared fixtures and a stub transport for the replay test suite.

The :class:`StubTransport` lets tests drive deterministic responses and
failures without any real network, which is exactly what keeps the replay
tests reproducible.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.model import CapturedExchange
from charon.replay import TransportRequest, TransportResponse


class StubTransport:
    """A scripted, in-memory transport.

    Either returns a fixed response, or invokes a handler that may return a
    :class:`TransportResponse` or raise a replay transport error. Records the
    last request it was given so tests can assert on applied auth headers.
    """

    def __init__(
        self,
        response: TransportResponse | None = None,
        handler: Callable[[TransportRequest], TransportResponse] | None = None,
    ) -> None:
        self._response = response
        self._handler = handler
        self.last_request: TransportRequest | None = None
        self.call_count = 0

    def send(self, request: TransportRequest) -> TransportResponse:
        self.last_request = request
        self.call_count += 1
        if self._handler is not None:
            return self._handler(request)
        if self._response is not None:
            return self._response
        return TransportResponse(status_code=200)


@pytest.fixture
def exchange() -> CapturedExchange:
    recorder = CaptureRecorder()
    raw = RawExchange(
        account_label="userA",
        method="GET",
        url="https://api.example.test/api/invoices/8821",
        status_code=200,
        request=RawMessage(
            headers=(("Authorization", "Bearer userA-secret"), ("Accept", "*/*")),
        ),
        response=RawMessage(body=b'{"id":8821}'),
    )
    return recorder.record(raw)
