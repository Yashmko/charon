"""Tests for DetectionInput consistency checks and helpers."""

from __future__ import annotations

import pytest

from charon.detect import DetectionInput

from tests.detect.conftest import (
    make_baseline,
    make_replay_request,
    make_replay_result,
)
from charon.compare import ComparisonEngine


def test_is_cross_identity_true_when_labels_differ(bola_input: DetectionInput) -> None:
    assert bola_input.is_cross_identity


def test_is_cross_identity_false_for_same_account() -> None:
    baseline = make_baseline(account_label="userA")
    request = make_replay_request(baseline, identity_label="userA")
    result = make_replay_result(baseline, request)
    comparison = ComparisonEngine().compare(baseline, result)
    item = DetectionInput(
        comparison=comparison,
        baseline_exchange=baseline,
        replay_request=request,
        replay_result=result,
    )
    assert not item.is_cross_identity


def test_mismatched_baseline_is_rejected() -> None:
    baseline = make_baseline()
    other_baseline = make_baseline(account_label="userZ")
    request = make_replay_request(baseline)
    result = make_replay_result(baseline, request)
    comparison = ComparisonEngine().compare(baseline, result)
    with pytest.raises(ValueError):
        DetectionInput(
            comparison=comparison,
            baseline_exchange=other_baseline,
            replay_request=request,
            replay_result=result,
        )
