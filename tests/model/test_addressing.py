"""Tests for deterministic content-addressing."""

from __future__ import annotations

import pytest

from charon.model import content_address
from charon.model.addressing import canonical_json


def test_address_is_deterministic_and_prefixed() -> None:
    payload = {"b": 1, "a": [1, 2, 3]}
    first = content_address(payload)
    second = content_address(payload)
    assert first == second
    assert first.startswith("sha256:")


def test_address_is_insensitive_to_key_order() -> None:
    assert content_address({"a": 1, "b": 2}) == content_address({"b": 2, "a": 1})


def test_address_changes_with_content() -> None:
    assert content_address({"a": 1}) != content_address({"a": 2})


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError):
        canonical_json(float("nan"))
