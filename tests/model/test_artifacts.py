"""Tests for the deterministic artifact types and their provenance/ids."""

from __future__ import annotations

import dataclasses

import pytest

from charon.model import (
    AccessDecision,
    CapturedExchange,
    Comparison,
    Evidence,
    HttpMessage,
    ModelError,
    Provenance,
    ReplayResult,
    ResponseSnapshot,
)


def test_captured_exchange_is_observed_and_immutable(
    captured_exchange: CapturedExchange,
) -> None:
    assert captured_exchange.provenance is Provenance.OBSERVED
    assert captured_exchange.exchange_id.startswith("sha256:")
    assert captured_exchange.method == "GET"  # normalized to upper-case
    with pytest.raises(dataclasses.FrozenInstanceError):
        captured_exchange.url = "https://other.test"  # type: ignore[misc]


def test_captured_exchange_id_is_stable_across_equivalent_records() -> None:
    def build(header_case: str) -> CapturedExchange:
        return CapturedExchange(
            account_label="userA",
            method="GET",
            url="https://example.test/x",
            request=HttpMessage(headers=((header_case, "v"),)),
            status_code=200,
            response=HttpMessage(body="{}"),
        )

    # Header-name casing must not change the content address.
    assert build("Authorization").exchange_id == build("authorization").exchange_id


def test_replay_result_records_nondeterminism(replay_result: ReplayResult) -> None:
    assert replay_result.provenance is Provenance.REPLAYED
    assert not replay_result.has_observed_nondeterminism
    flagged = dataclasses.replace(
        replay_result, nondeterminism_notes=("volatile: response.body.timestamp",)
    )
    assert flagged.has_observed_nondeterminism


def test_comparison_is_derived_and_detects_difference(
    captured_exchange: CapturedExchange, replay_result: ReplayResult
) -> None:
    same = Comparison(
        baseline_ref=captured_exchange.exchange_id,
        other_ref=replay_result.result_id,
        baseline=ResponseSnapshot(200, AccessDecision.GRANTED),
        other=ResponseSnapshot(200, AccessDecision.GRANTED),
    )
    assert same.provenance is Provenance.DERIVED
    assert not same.differs

    differing = Comparison(
        baseline_ref=captured_exchange.exchange_id,
        other_ref=replay_result.result_id,
        baseline=ResponseSnapshot(403, AccessDecision.DENIED),
        other=ResponseSnapshot(200, AccessDecision.GRANTED),
    )
    assert differing.differs


def test_evidence_requires_comparison_and_exchange(
    captured_exchange: CapturedExchange, comparison: Comparison
) -> None:
    with pytest.raises(ModelError):
        Evidence(comparison_ref="", captured_exchange_refs=(captured_exchange.exchange_id,))
    with pytest.raises(ModelError):
        Evidence(comparison_ref=comparison.comparison_id, captured_exchange_refs=())


def test_evidence_is_derived(evidence: Evidence) -> None:
    assert evidence.provenance is Provenance.DERIVED
    assert evidence.evidence_id.startswith("sha256:")
