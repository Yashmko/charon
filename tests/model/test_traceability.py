"""Tests that the full audit chain is walkable and LLM-free.

Verifies: Finding -> Evidence -> Comparison -> (ReplayRequest, ReplayResult)
-> CapturedExchange, with every deterministic artifact carrying a
non-Inferred provenance.
"""

from __future__ import annotations

from charon.model import (
    CapturedExchange,
    Comparison,
    Evidence,
    Finding,
    OwaspClass,
    Provenance,
    Provenanced,
    ReplayRequest,
    ReplayResult,
    Severity,
)


def test_full_audit_chain_links_resolve(
    captured_exchange: CapturedExchange,
    replay_request: ReplayRequest,
    replay_result: ReplayResult,
    comparison: Comparison,
    evidence: Evidence,
) -> None:
    finding = Finding.create(
        rule_id="bola.cross-account-read",
        owasp_class=OwaspClass.API1_BOLA,
        severity=Severity.HIGH,
        subject={"path_template": Provenanced.observed("/api/invoices/{id}")},
        evidence=[evidence],
    )

    # Finding -> Evidence
    assert evidence.evidence_id in finding.evidence_ids
    # Evidence -> Comparison
    assert evidence.comparison_ref == comparison.comparison_id
    # Evidence -> CapturedExchange
    assert captured_exchange.exchange_id in evidence.captured_exchange_refs
    # Evidence -> (ReplayRequest, ReplayResult)
    assert (replay_request.request_id, replay_result.result_id) in evidence.replay_pairs
    # Comparison -> ReplayResult ; ReplayResult -> ReplayRequest -> Exchange
    assert comparison.other_ref == replay_result.result_id
    assert replay_result.replay_request_id == replay_request.request_id
    assert replay_request.source_exchange_id == captured_exchange.exchange_id
    assert replay_result.baseline_exchange_id == captured_exchange.exchange_id

    # No deterministic link in the chain is LLM-generated.
    for artifact in (captured_exchange, replay_result, comparison, evidence):
        assert artifact.provenance is not Provenance.INFERRED
