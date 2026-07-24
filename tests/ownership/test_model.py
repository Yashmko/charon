"""Tests for the ownership data model."""

from __future__ import annotations

import pytest
from charon.ownership import OwnershipInference, OwnershipMap

ContentAddress = str


def _inference(
    url: str = "https://api.example.test/resource/1",
    owning_account: str = "userA",
    source_field: str = "body.owner_id",
    confidence: float = 0.85,
    source_exchange_id: ContentAddress = "sha256:exchange1",
) -> OwnershipInference:
    return OwnershipInference(
        url=url,
        owning_account=owning_account,
        source_field=source_field,
        source_exchange_id=source_exchange_id,
        confidence=confidence,
    )


class TestOwnershipInference:
    def test_minimal_construction(self) -> None:
        inf = OwnershipInference(
            url="https://example.test/res/1",
            owning_account="userA",
            source_field="body.owner_id",
            source_exchange_id="sha256:abc",
        )
        assert inf.url == "https://example.test/res/1"
        assert inf.owning_account == "userA"
        assert inf.source_field == "body.owner_id"
        assert inf.source_exchange_id == "sha256:abc"
        assert inf.confidence == 0.85  # default

    def test_custom_confidence(self) -> None:
        inf = OwnershipInference(
            url="https://example.test/res/1",
            owning_account="userA",
            source_field="body.owner_id",
            source_exchange_id="sha256:abc",
            confidence=0.6,
        )
        assert inf.confidence == 0.6

    def test_immutable(self) -> None:
        inf = _inference()
        with pytest.raises(AttributeError):
            inf.owning_account = "userB"  # type: ignore[misc]


class TestOwnershipMap:
    def test_empty_map(self) -> None:
        om = OwnershipMap()
        assert om.count == 0
        assert om.owner_of("https://example.test/res") is None
        assert om.is_account_owner("https://example.test/res", "userA") is None
        assert om.resources_owned_by("userA") == ()

    def test_single_inference(self) -> None:
        inf = _inference()
        om = OwnershipMap(inferences=(inf,))
        assert om.count == 1
        assert om.owner_of(inf.url) == "userA"
        assert om.is_account_owner(inf.url, "userA") is True
        assert om.is_account_owner(inf.url, "userB") is False
        assert om.resources_owned_by("userA") == (inf,)
        assert om.resources_owned_by("userB") == ()

    def test_multiple_inferences_different_urls(self) -> None:
        inf1 = _inference(url="https://example.test/res/1", owning_account="userA")
        inf2 = _inference(url="https://example.test/res/2", owning_account="userB")
        om = OwnershipMap(inferences=(inf1, inf2))
        assert om.count == 2
        assert om.owner_of("https://example.test/res/1") == "userA"
        assert om.owner_of("https://example.test/res/2") == "userB"
        assert om.owner_of("https://example.test/res/3") is None

    def test_highest_confidence_wins_for_same_url(self) -> None:
        inf1 = _inference(
            url="https://example.test/res/1",
            owning_account="userA",
            confidence=0.6,
        )
        inf2 = _inference(
            url="https://example.test/res/1",
            owning_account="userB",
            confidence=0.85,
        )
        # Two different accounts both claiming the same URL.
        # The higher-confidence inference (userB) wins.
        om = OwnershipMap(inferences=(inf1, inf2))
        assert om.owner_of("https://example.test/res/1") == "userB"

    def test_inferences_sorted_by_url_then_account(self) -> None:
        inf_a = _inference(
            url="https://example.test/res/b",
            owning_account="userA",
        )
        inf_b = _inference(
            url="https://example.test/res/a",
            owning_account="userB",
        )
        om = OwnershipMap(inferences=(inf_b, inf_a))
        # Should be sorted: res/a first, then res/b.
        assert om.inferences[0].url == "https://example.test/res/a"
        assert om.inferences[1].url == "https://example.test/res/b"

    def test_is_account_owner_returns_none_for_unknown_url(self) -> None:
        om = OwnershipMap()
        assert om.is_account_owner("https://example.test/unknown", "userA") is None

    def test_is_account_owner_returns_true_when_account_owns(self) -> None:
        inf = _inference(url="https://example.test/res/1", owning_account="userA")
        om = OwnershipMap(inferences=(inf,))
        assert om.is_account_owner("https://example.test/res/1", "userA") is True

    def test_is_account_owner_returns_false_when_other_owns(self) -> None:
        inf = _inference(url="https://example.test/res/1", owning_account="userB")
        om = OwnershipMap(inferences=(inf,))
        assert om.is_account_owner("https://example.test/res/1", "userA") is False

    def test_resources_owned_by_returns_only_matching(self) -> None:
        inf1 = _inference(
            url="https://example.test/res/1",
            owning_account="userA",
            source_field="body.owner_id",
        )
        inf2 = _inference(
            url="https://example.test/res/2",
            owning_account="userB",
            source_field="body.owner_id",
        )
        inf3 = _inference(
            url="https://example.test/res/3",
            owning_account="userA",
            source_field="body.user_id",
        )
        om = OwnershipMap(inferences=(inf1, inf2, inf3))
        owned_by_a = om.resources_owned_by("userA")
        assert len(owned_by_a) == 2
        assert owned_by_a[0].url == "https://example.test/res/1"
        assert owned_by_a[1].url == "https://example.test/res/3"

    def test_empty_inferences_is_empty(self) -> None:
        om = OwnershipMap(inferences=())
        assert om.count == 0

    def test_count_matches_inference_count(self) -> None:
        infs = tuple(_inference(url=f"https://example.test/res/{i}") for i in range(5))
        om = OwnershipMap(inferences=infs)
        assert om.count == 5
