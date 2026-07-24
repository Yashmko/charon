"""Shared builders for the ownership test suite.

Produces real ``CapturedExchange`` objects (via the capture recorder) with
various response body shapes so engine tests exercise genuine model
artifacts.
"""

from __future__ import annotations

import pytest
from charon.capture import CaptureRecorder, RawExchange, RawMessage
from charon.model import CapturedExchange


def make_exchange(
    *,
    account_label: str = "userA",
    url: str = "https://api.example.test/api/invoices/8821",
    response_body: bytes | None = b'{"owner_id": "userA"}',
    status_code: int = 200,
    method: str = "GET",
) -> CapturedExchange:
    """Build a ``CapturedExchange`` with the given response body.

    The request carries a minimal ``Authorization`` header so the exchange
    looks realistic. Response headers include ``Content-Type: application/json``
    when the body looks like JSON, so the engine can parse it.
    """
    content_type: tuple[tuple[str, str], ...] = (
        (("Content-Type", "application/json"),)
        if response_body is not None and b"{" in response_body
        else ()
    )
    recorder = CaptureRecorder()
    return recorder.record(
        RawExchange(
            account_label=account_label,
            method=method,
            url=url,
            status_code=status_code,
            request=RawMessage(
                headers=(
                    ("Accept", "application/json"),
                    ("Authorization", "Bearer test-token"),
                ),
            ),
            response=RawMessage(
                headers=content_type,
                body=response_body,
            ),
        )
    )


@pytest.fixture
def owner_field_exchange() -> CapturedExchange:
    """Exchange where ``owner_id`` matches the account label."""
    return make_exchange(
        account_label="userA",
        response_body=b'{"id": 8821, "owner_id": "userA", "title": "Invoice 8821"}',
    )


@pytest.fixture
def no_match_exchange() -> CapturedExchange:
    """Exchange with no owner fields matching the account label."""
    return make_exchange(
        account_label="userA",
        response_body=b'{"id": 8821, "owner_id": "userB", "title": "Invoice 8821"}',
    )


@pytest.fixture
def account_value_exchange() -> CapturedExchange:
    """Exchange where the account label appears as a non-owner field value."""
    return make_exchange(
        account_label="userA",
        response_body=b'{"id": 8821, "created_by": "admin", "assigned_to": "userA"}',
    )


@pytest.fixture
def no_body_exchange() -> CapturedExchange:
    """Exchange with no response body."""
    return make_exchange(
        account_label="userA",
        response_body=None,
    )


@pytest.fixture
def non_json_body_exchange() -> CapturedExchange:
    """Exchange with a non-JSON response body (plain text)."""
    return make_exchange(
        account_label="userA",
        response_body=b"OK",
    )


@pytest.fixture
def array_body_exchange() -> CapturedExchange:
    """Exchange with a JSON array response body."""
    return make_exchange(
        account_label="userA",
        response_body=(
            b'[{"owner_id": "userA", "item": "a"},'
            b' {"owner_id": "userB", "item": "b"}]'
        ),
    )


@pytest.fixture
def nested_body_exchange() -> CapturedExchange:
    """Exchange with a nested JSON response body."""
    return make_exchange(
        account_label="userA",
        response_body=(
            b'{"data": {"owner_id": "userA", '
            b'"details": {"user_id": "userA", "modified_by": "admin"}}}'
        ),
    )
