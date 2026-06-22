"""Shared builders for the report test suite.

Assembles a real capture -> replay -> compare -> detect chain so the report
tests render genuine findings and artifacts with full traceability.
"""

from __future__ import annotations

import pytest

from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.compare import ComparisonEngine
from charon.detect import DetectionEngine, DetectionInput
from charon.model import (
    CapturedExchange,
    Comparison,
    Finding,
    HttpMessage,
    ReplayIdentity,
    ReplayRequest,
    ReplayResult,
)
from charon.report import ArtifactIndex

_JSON = (("Content-Type", "application/json"),)
_BODY = b'{"id": 8821, "owner": "userA"}'


class Chain:
    """A fully-linked pipeline run, exposing every artifact for indexing."""

    def __init__(
        self,
        baseline: CapturedExchange,
        request: ReplayRequest,
        result: ReplayResult,
        comparison: Comparison,
        finding: Finding,
    ) -> None:
        self.baseline = baseline
        self.request = request
        self.result = result
        self.comparison = comparison
        self.finding = finding

    def index(self) -> ArtifactIndex:
        return ArtifactIndex(
            captured_exchanges=[self.baseline],
            replay_requests=[self.request],
            replay_results=[self.result],
            comparisons=[self.comparison],
            evidence=list(self.finding.evidence),
        )


def build_chain(
    *,
    baseline_account: str = "userA",
    replay_identity: str = "userB",
) -> Chain:
    recorder = CaptureRecorder()
    baseline = recorder.record(
        RawExchange(
            account_label=baseline_account,
            method="GET",
            url="https://api.example.test/api/invoices/8821",
            status_code=200,
            request=RawMessage(headers=_JSON),
            response=RawMessage(headers=_JSON, body=_BODY),
        )
    )
    request = ReplayRequest(
        source_exchange_id=baseline.exchange_id,
        identity=ReplayIdentity(label=replay_identity),
        method=baseline.method,
        url=baseline.url,
        request=HttpMessage(headers=_JSON),
    )
    result = ReplayResult(
        replay_request_id=request.request_id,
        baseline_exchange_id=baseline.exchange_id,
        status_code=200,
        response=HttpMessage(headers=_JSON, body=_BODY),
    )
    comparison = ComparisonEngine().compare(baseline, result)
    item = DetectionInput(
        comparison=comparison,
        baseline_exchange=baseline,
        replay_request=request,
        replay_result=result,
    )
    (finding,) = DetectionEngine().detect([item])
    return Chain(baseline, request, result, comparison, finding)


@pytest.fixture
def chain() -> Chain:
    return build_chain()
