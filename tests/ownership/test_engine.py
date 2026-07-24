"""Tests for the deterministic ownership inference engine."""

from __future__ import annotations

from charon.model import CapturedExchange
from charon.ownership import OwnershipConfig, OwnershipEngine, OwnershipMap

from tests.ownership.conftest import make_exchange


def _analyze(
    *exchanges: CapturedExchange,
    config: OwnershipConfig | None = None,
) -> OwnershipMap:
    return OwnershipEngine(config=config).analyze(exchanges)


class TestOwnerFieldMatch:
    """Tests for the primary owner-field pattern inference pass."""

    def test_owner_field_matches_account_label(
        self, owner_field_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(owner_field_exchange)
        assert om.count == 1
        inf = om.inferences[0]
        assert inf.owning_account == "userA"
        assert inf.confidence == 0.85  # owner_confidence default
        assert "owner_id" in inf.source_field

    def test_owner_field_does_not_match_different_account(
        self, no_match_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(no_match_exchange)
        # owner_id = "userB", account_label = "userA" -> no match
        assert om.count == 0

    def test_no_body_produces_no_inferences(
        self, no_body_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(no_body_exchange)
        assert om.count == 0

    def test_non_json_body_produces_no_inferences(
        self, non_json_body_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(non_json_body_exchange)
        assert om.count == 0


class TestAccountLabelValueMatch:
    """Tests for the secondary account-label value inference pass."""

    def test_account_label_found_in_non_owner_field(
        self, account_value_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(account_value_exchange)
        # "assigned_to": "userA" matches account_label "userA"
        # But "created_by": "admin" and "owner_id" not present.
        # "assigned_to" is not a configured owner field, so it should match
        # at account_label_confidence (0.6).
        assert om.count == 1
        inf = om.inferences[0]
        assert inf.owning_account == "userA"
        assert inf.confidence == 0.6  # account_label_confidence default
        assert "assigned_to" in inf.source_field

    def test_owner_field_has_priority_over_value_match(
        self, owner_field_exchange: CapturedExchange,
    ) -> None:
        """When both passes could match, the higher-confidence owner-field
        inference wins and the lower-confidence value-match is skipped."""
        om = _analyze(owner_field_exchange)
        assert om.count == 1
        # owner_id = "userA" should match at 0.85 (owner_field pattern).
        # The account_label "userA" also appears as a value, but should
        # not produce a second inference.
        inf = om.inferences[0]
        assert inf.confidence == 0.85
        assert "owner_id" in inf.source_field


class TestNestedAndArrayBodies:
    """Tests for non-dict JSON response bodies."""

    def test_nested_json_owner_field(
        self, nested_body_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(nested_body_exchange)
        # "data.owner_id": "userA" and "data.details.user_id": "userA"
        # Both match owner field patterns. But both have same URL + account,
        # so only the first (higher confidence, same level) is kept.
        # Actually both have the same confidence (0.85), so only the first
        # one encountered (owner_id) is kept.
        assert om.count >= 1
        for inf in om.inferences:
            assert inf.owning_account == "userA"
            assert inf.confidence == 0.85

    def test_array_body_scans_elements(
        self, array_body_exchange: CapturedExchange,
    ) -> None:
        om = _analyze(array_body_exchange)
        # [{"owner_id": "userA", ...}, {"owner_id": "userB", ...}]
        # First element owner_id = "userA" matches -> inference at 0.85.
        # Second element owner_id = "userB" doesn't match "userA".
        assert om.count == 1
        inf = om.inferences[0]
        assert inf.owning_account == "userA"
        assert inf.confidence == 0.85


class TestMinConfidenceFilter:
    """Tests for the min_confidence output filter."""

    def test_inferences_below_threshold_filtered(self) -> None:
        exchange = make_exchange(
            account_label="userA",
            response_body=b'{"assigned_to": "userA"}',
        )
        # account_label_confidence = 0.6, min_confidence = 0.7
        config = OwnershipConfig(account_label_confidence=0.6, min_confidence=0.7)
        om = _analyze(exchange, config=config)
        assert om.count == 0

    def test_inferences_at_threshold_kept(self) -> None:
        exchange = make_exchange(
            account_label="userA",
            response_body=b'{"assigned_to": "userA"}',
        )
        config = OwnershipConfig(account_label_confidence=0.6, min_confidence=0.6)
        om = _analyze(exchange, config=config)
        assert om.count == 1

    def test_inferences_above_threshold_kept(self) -> None:
        exchange = make_exchange(
            account_label="userA",
            response_body=b'{"owner_id": "userA"}',
        )
        # owner_confidence = 0.85, min_confidence = 0.5
        om = _analyze(exchange)
        assert om.count == 1

    def test_zero_min_confidence_keeps_all(self) -> None:
        exchange = make_exchange(
            account_label="userA",
            response_body=b'{"name": "userA"}',
        )
        config = OwnershipConfig(account_label_confidence=0.6, min_confidence=0.0)
        om = _analyze(exchange, config=config)
        assert om.count == 1
        assert om.inferences[0].confidence == 0.6


class TestMultipleExchanges:
    """Tests for analyzing multiple exchanges at once."""

    def test_multiple_exchanges_accumulate(self) -> None:
        ex1 = make_exchange(
            account_label="userA",
            url="https://api.example.test/res/1",
            response_body=b'{"owner_id": "userA"}',
        )
        ex2 = make_exchange(
            account_label="userB",
            url="https://api.example.test/res/2",
            response_body=b'{"owner_id": "userB"}',
        )
        om = _analyze(ex1, ex2)
        assert om.count == 2
        owners = {inf.owning_account for inf in om.inferences}
        assert owners == {"userA", "userB"}

    def test_same_url_different_accounts(self) -> None:
        ex1 = make_exchange(
            account_label="userA",
            url="https://api.example.test/res/1",
            response_body=b'{"owner_id": "userA"}',
        )
        ex2 = make_exchange(
            account_label="userB",
            url="https://api.example.test/res/1",
            response_body=b'{"owner_id": "userB"}',
        )
        om = _analyze(ex1, ex2)
        assert om.count == 2

    def test_empty_exchanges(self) -> None:
        om = _analyze()
        assert om.count == 0

    def test_deterministic_across_runs(self) -> None:
        ex = make_exchange(
            account_label="userA",
            response_body=b'{"owner_id": "userA", "assigned_to": "userA"}',
        )
        first = _analyze(ex)
        second = _analyze(ex)
        assert len(first.inferences) == len(second.inferences)
        for i1, i2 in zip(first.inferences, second.inferences, strict=True):
            assert i1.url == i2.url
            assert i1.owning_account == i2.owning_account
            assert i1.confidence == i2.confidence
            assert i1.source_field == i2.source_field


class TestEdgeCases:
    """Tests for edge cases and corner conditions."""

    def test_account_label_in_nested_owner_field(self) -> None:
        ex = make_exchange(
            account_label="admin",
            response_body=b'{"data": {"owner": "admin"}}',
        )
        om = _analyze(ex)
        # "owner" is in the owner_field_patterns.
        assert om.count == 1
        assert om.inferences[0].owning_account == "admin"

    def test_account_label_not_in_body_at_all(self) -> None:
        ex = make_exchange(
            account_label="userA",
            response_body=b'{"id": 1, "title": "Hello"}',
        )
        om = _analyze(ex)
        assert om.count == 0

    def test_account_label_as_integer_in_body(self) -> None:
        """When account label is a string but body has it as an integer
        value, they should NOT match (value comparison is string only)."""
        ex = make_exchange(
            account_label="12345",
            response_body=b'{"id": 12345, "owner_id": "12345"}',
        )
        om = _analyze(ex)
        # "owner_id": "12345" matches as a string.
        assert om.count == 1
        assert om.inferences[0].owning_account == "12345"

    def test_configurable_owner_field_confidence(self) -> None:
        ex = make_exchange(
            account_label="userA",
            response_body=b'{"owner_id": "userA"}',
        )
        config = OwnershipConfig(owner_confidence=0.95)
        om = _analyze(ex, config=config)
        assert om.inferences[0].confidence == 0.95

    def test_configurable_account_label_confidence(self) -> None:
        ex = make_exchange(
            account_label="userA",
            response_body=b'{"assigned_to": "userA"}',
        )
        config = OwnershipConfig(account_label_confidence=0.75)
        om = _analyze(ex, config=config)
        assert om.inferences[0].confidence == 0.75

    def test_owner_field_with_non_matching_value(self) -> None:
        ex = make_exchange(
            account_label="userA",
            response_body=b'{"owner_id": "userB"}',
        )
        om = _analyze(ex)
        assert om.count == 0
