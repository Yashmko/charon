"""Tests for the mechanical AccessDecision classification."""

from __future__ import annotations

import pytest

from charon.compare import classify_access_decision
from charon.model import AccessDecision


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, AccessDecision.GRANTED),
        (201, AccessDecision.GRANTED),
        (204, AccessDecision.GRANTED),
        (299, AccessDecision.GRANTED),
        (401, AccessDecision.DENIED),
        (403, AccessDecision.DENIED),
        (404, AccessDecision.DENIED),
        (301, AccessDecision.INDETERMINATE),
        (302, AccessDecision.INDETERMINATE),
        (400, AccessDecision.INDETERMINATE),
        (418, AccessDecision.INDETERMINATE),
        (500, AccessDecision.INDETERMINATE),
        (100, AccessDecision.INDETERMINATE),
    ],
)
def test_classify_access_decision(
    status: int, expected: AccessDecision
) -> None:
    assert classify_access_decision(status) is expected
