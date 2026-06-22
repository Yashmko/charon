"""Shared builders for the compare test suite.

These helpers assemble real ``CapturedExchange`` and ``ReplayResult``
artifacts via the capture/replay-adjacent model APIs so the comparison tests
exercise genuine inputs rather than hand-mocked stand-ins.
"""

from __future__ import annotations

import pytest

from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.compare import ComparisonEngine
from charon.model import CapturedExchange, HttpMessage, ReplayResult


@pytest.fixture
def engine() -> ComparisonEngine:
    return ComparisonEngine()


def make_exchange(
    *,
    status_code: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes | None = None,
) -> CapturedExchange:
    """Build a baseline CapturedExchange with the given response shape."""
    recorder = CaptureRecorder()
    return recorder.record(
        RawExchange(
            account_label="userA",
            method="GET",
            url="https://api.example.test/api/invoices/8821",
            status_code=status_code,
            request=RawMessage(),
            response=RawMessage(headers=headers, body=body),
        )
    )


def make_replay_result(
    baseline: CapturedExchange,
    *,
    status_code: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes | None = None,
    nondeterminism_notes: tuple[str, ...] = (),
) -> ReplayResult:
    """Build a ReplayResult to compare against ``baseline``."""
    return ReplayResult(
        replay_request_id="sha256:replayrequest",
        baseline_exchange_id=baseline.exchange_id,
        status_code=status_code,
        response=HttpMessage(headers=headers, body=body),
        nondeterminism_notes=nondeterminism_notes,
    )
