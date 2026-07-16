"""Tests for the provenance tagging primitives."""

from __future__ import annotations

import dataclasses

import pytest
from charon.model import Provenance, Provenanced


def test_inferred_is_advisory_others_are_deterministic() -> None:
    assert Provenance.INFERRED.is_advisory
    assert not Provenance.INFERRED.is_deterministic
    for member in (Provenance.OBSERVED, Provenance.REPLAYED, Provenance.DERIVED):
        assert member.is_deterministic
        assert not member.is_advisory


def test_provenanced_helpers_set_expected_source() -> None:
    assert Provenanced.observed("x").source is Provenance.OBSERVED
    assert Provenanced.replayed("x").source is Provenance.REPLAYED
    assert Provenanced.derived("x").source is Provenance.DERIVED
    assert Provenanced.inferred("x").source is Provenance.INFERRED
    assert Provenanced.inferred("x").is_advisory


def test_provenanced_is_immutable() -> None:
    tagged = Provenanced.observed("x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        tagged.value = "y"  # type: ignore[misc]
