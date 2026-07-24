"""Tests for the deterministic ownership configuration."""

from __future__ import annotations

from charon.ownership import OwnershipConfig


def test_default_config_values() -> None:
    config = OwnershipConfig()
    assert config.owner_confidence == 0.85
    assert config.account_label_confidence == 0.6
    assert config.min_confidence == 0.5


def test_is_owner_field_matches_case_insensitively() -> None:
    config = OwnershipConfig()
    assert config.is_owner_field("owner_id")
    assert config.is_owner_field("OWNER_ID")
    assert config.is_owner_field("Owner_Id")
    assert config.is_owner_field("userId")
    assert config.is_owner_field("userid")
    assert config.is_owner_field("customer_id")


def test_is_owner_field_rejects_non_owner_names() -> None:
    config = OwnershipConfig()
    assert not config.is_owner_field("title")
    assert not config.is_owner_field("id")
    assert not config.is_owner_field("email")
    assert not config.is_owner_field("name")


def test_custom_owner_field_patterns() -> None:
    config = OwnershipConfig(
        owner_field_patterns=frozenset({"custom_owner", "belongs_to"}),
    )
    assert config.is_owner_field("custom_owner")
    assert config.is_owner_field("belongs_to")
    assert not config.is_owner_field("owner_id")
    assert not config.is_owner_field("userId")


def test_custom_confidence_values() -> None:
    config = OwnershipConfig(
        owner_confidence=0.9,
        account_label_confidence=0.7,
        min_confidence=0.6,
    )
    assert config.owner_confidence == 0.9
    assert config.account_label_confidence == 0.7
    assert config.min_confidence == 0.6


def test_owner_field_patterns_normalized_to_lowercase() -> None:
    config = OwnershipConfig(
        owner_field_patterns=frozenset({"OWNER_ID", "UserId"}),
    )
    # After __post_init__, patterns are lower-cased.
    assert "owner_id" in config.owner_field_patterns
    assert "userid" in config.owner_field_patterns
    assert "OWNER_ID" not in config.owner_field_patterns
