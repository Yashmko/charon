"""Tests for the ComparisonEngine."""

from __future__ import annotations

from charon.compare import ComparisonConfig, ComparisonEngine
from charon.model import AccessDecision, Comparison, Provenance

from tests.compare.conftest import make_exchange, make_replay_result


def _locations(comparison: Comparison) -> set[str]:
    return {d.location for d in comparison.field_diffs}


def _diff_map(
    comparison: Comparison,
) -> dict[str, tuple[str | None, str | None]]:
    return {
        d.location: (d.baseline_value, d.other_value)
        for d in comparison.field_diffs
    }


def test_identical_responses_have_no_field_diffs(
    engine: ComparisonEngine,
) -> None:
    body = b'{"id": 8821, "owner": "userA"}'
    headers = (("Content-Type", "application/json"),)
    baseline = make_exchange(status_code=200, headers=headers, body=body)
    replay = make_replay_result(
        baseline, status_code=200, headers=headers, body=body
    )
    comparison = engine.compare(baseline, replay)

    assert isinstance(comparison, Comparison)
    assert comparison.provenance is Provenance.DERIVED
    assert comparison.baseline_ref == baseline.exchange_id
    assert comparison.other_ref == replay.result_id
    assert comparison.field_diffs == ()
    assert not comparison.differs


def test_status_code_difference_is_reported(engine: ComparisonEngine) -> None:
    baseline = make_exchange(status_code=403)
    replay = make_replay_result(baseline, status_code=200)
    comparison = engine.compare(baseline, replay)

    assert "status_code" in _locations(comparison)
    assert comparison.baseline.access_decision is AccessDecision.DENIED
    assert comparison.other.access_decision is AccessDecision.GRANTED
    assert comparison.differs


def test_header_difference_is_reported(engine: ComparisonEngine) -> None:
    baseline = make_exchange(headers=(("X-Scope", "owner"),))
    replay = make_replay_result(baseline, headers=(("X-Scope", "public"),))
    comparison = engine.compare(baseline, replay)

    diffs = _diff_map(comparison)
    assert diffs["header.x-scope"] == ("owner", "public")


def test_volatile_headers_are_ignored(engine: ComparisonEngine) -> None:
    baseline = make_exchange(
        headers=(("Date", "Mon, 01 Jan 2024 00:00:00 GMT"),)
    )
    replay = make_replay_result(
        baseline, headers=(("Date", "Tue, 02 Jan 2024 09:09:09 GMT"),)
    )
    comparison = engine.compare(baseline, replay)
    assert "header.date" not in _locations(comparison)
    assert comparison.field_diffs == ()


def test_json_body_field_diffs(engine: ComparisonEngine) -> None:
    baseline = make_exchange(
        headers=(("Content-Type", "application/json"),),
        body=b'{"owner": "userA", "amount": 100}',
    )
    replay = make_replay_result(
        baseline,
        headers=(("Content-Type", "application/json"),),
        body=b'{"owner": "userB", "amount": 100}',
    )
    comparison = engine.compare(baseline, replay)
    diffs = _diff_map(comparison)
    assert diffs["body.owner"] == ('"userA"', '"userB"')
    assert "body.amount" not in diffs


def test_volatile_body_keys_are_ignored(engine: ComparisonEngine) -> None:
    baseline = make_exchange(
        headers=(("Content-Type", "application/json"),),
        body=b'{"id": 1, "timestamp": "2024-01-01T00:00:00Z"}',
    )
    replay = make_replay_result(
        baseline,
        headers=(("Content-Type", "application/json"),),
        body=b'{"id": 1, "timestamp": "2024-06-22T10:10:10Z"}',
    )
    comparison = engine.compare(baseline, replay)
    assert "body.timestamp" not in _locations(comparison)
    assert "body.id" not in _locations(comparison)
    assert comparison.field_diffs == ()


def test_binary_body_compared_by_digest(engine: ComparisonEngine) -> None:
    baseline = make_exchange(body=b"\x89PNG\r\n\x1a\n\x00\x01")
    replay = make_replay_result(baseline, body=b"\x89PNG\r\n\x1a\n\x99\x98")
    comparison = engine.compare(baseline, replay)
    locations = _locations(comparison)
    assert "body.sha256" in locations
    digest_diff = next(
        d for d in comparison.field_diffs if d.location == "body.sha256"
    )
    assert digest_diff.baseline_value is not None
    assert digest_diff.baseline_value.startswith("sha256:")
    assert digest_diff.baseline_value != digest_diff.other_value


def test_identical_binary_body_has_no_digest_diff(
    engine: ComparisonEngine,
) -> None:
    raw = b"\x00\x01\x02\x03binary"
    baseline = make_exchange(body=raw)
    replay = make_replay_result(baseline, body=raw)
    comparison = engine.compare(baseline, replay)
    assert "body.sha256" not in _locations(comparison)


def test_content_length_difference_reported(engine: ComparisonEngine) -> None:
    baseline = make_exchange(body=b"short")
    replay = make_replay_result(baseline, body=b"a much longer body")
    comparison = engine.compare(baseline, replay)
    diffs = _diff_map(comparison)
    assert diffs["body.length"] == ("5", "18")


def test_malformed_json_falls_back_to_digest(engine: ComparisonEngine) -> None:
    baseline = make_exchange(
        headers=(("Content-Type", "application/json"),), body=b"{not json"
    )
    replay = make_replay_result(
        baseline,
        headers=(("Content-Type", "application/json"),),
        body=b"{also not json",
    )
    comparison = engine.compare(baseline, replay)
    # Neither body parsed as JSON, so it falls back to a digest comparison.
    assert "body.sha256" in _locations(comparison)


def test_redirect_chain_reported(engine: ComparisonEngine) -> None:
    baseline = make_exchange()
    replay = make_replay_result(
        baseline,
        nondeterminism_notes=("redirect-chain: https://api.example.test/old",),
    )
    comparison = engine.compare(baseline, replay)
    diffs = {d.location: d.other_value for d in comparison.field_diffs}
    assert "redirect" in diffs
    assert diffs["redirect"] is not None
    assert "redirect-chain" in diffs["redirect"]


def test_comparison_is_deterministic(engine: ComparisonEngine) -> None:
    baseline = make_exchange(
        headers=(("Content-Type", "application/json"), ("X-Scope", "owner")),
        body=b'{"owner": "userA", "items": [1, 2, 3]}',
    )
    replay = make_replay_result(
        baseline,
        status_code=200,
        headers=(("Content-Type", "application/json"), ("X-Scope", "public")),
        body=b'{"owner": "userB", "items": [1, 2, 4]}',
    )
    first = engine.compare(baseline, replay)
    second = engine.compare(baseline, replay)
    assert first.comparison_id == second.comparison_id
    assert first.field_diffs == second.field_diffs


def test_engine_does_not_mutate_inputs(engine: ComparisonEngine) -> None:
    baseline = make_exchange(body=b'{"a": 1}')
    replay = make_replay_result(baseline, body=b'{"a": 2}')
    baseline_id_before = baseline.exchange_id
    replay_id_before = replay.result_id
    engine.compare(baseline, replay)
    assert baseline.exchange_id == baseline_id_before
    assert replay.result_id == replay_id_before


def test_custom_config_can_treat_header_as_volatile() -> None:
    config = ComparisonConfig(volatile_headers=frozenset({"x-scope"}))
    engine = ComparisonEngine(config)
    baseline = make_exchange(headers=(("X-Scope", "owner"),))
    replay = make_replay_result(baseline, headers=(("X-Scope", "public"),))
    comparison = engine.compare(baseline, replay)
    assert "header.x-scope" not in _locations(comparison)
