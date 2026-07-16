"""Shared fixtures for the capture test suite."""

from __future__ import annotations

import pytest
from charon.capture import CaptureRecorder


@pytest.fixture
def recorder() -> CaptureRecorder:
    return CaptureRecorder()
