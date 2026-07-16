"""Tests for the CaptureRecorder conversion path."""

from __future__ import annotations

import pytest
from charon.capture import (
    CaptureConfig,
    CaptureRecorder,
    HeaderAction,
    MalformedExchangeError,
    RawExchange,
    RawMessage,
)
from charon.capture.config import REDACTED_PLACEHOLDER
from charon.model import CapturedExchange, Provenance


def _raw(**overrides: object) -> RawExchange:
    base: dict[str, object] = dict(
        account_label="userA",
        method="get",
        url="HTTPS://API.Example.test:443/api/orders/8821?b=2&a=1",
        status_code=200,
    )
    base.update(overrides)
    return RawExchange(
        account_label=str(base["account_label"]),
        method=str(base["method"]),
        url=str(base["url"]),
        status_code=int(str(base["status_code"])),
        request=base.get("request", RawMessage()),  # type: ignore[arg-type]
        response=base.get("response", RawMessage()),  # type: ignore[arg-type]
    )


def test_record_produces_observed_captured_exchange(
    recorder: CaptureRecorder,
) -> None:
    exchange = recorder.record(_raw())
    assert isinstance(exchange, CapturedExchange)
    assert exchange.provenance is Provenance.OBSERVED
    assert exchange.method == "GET"
    assert exchange.url == "https://api.example.test/api/orders/8821?a=1&b=2"
    assert exchange.exchange_id.startswith("sha256:")


def test_record_is_deterministic_for_identical_traffic(
    recorder: CaptureRecorder,
) -> None:
    first = recorder.record(_raw())
    second = recorder.record(_raw())
    assert first.exchange_id == second.exchange_id
    assert first == second


def test_record_id_is_stable_across_header_order_and_url_casing(
    recorder: CaptureRecorder,
) -> None:
    a = recorder.record(
        _raw(
            url="https://api.example.test/api/orders/8821?a=1&b=2",
            request=RawMessage(headers=(("X-A", "1"), ("X-B", "2"))),
        )
    )
    b = recorder.record(
        _raw(
            url="HTTPS://API.EXAMPLE.TEST/api/orders/8821?b=2&a=1",
            request=RawMessage(headers=(("x-b", "2"), ("x-a", "1"))),
        )
    )
    assert a.exchange_id == b.exchange_id


def test_record_extracts_resource_refs(recorder: CaptureRecorder) -> None:
    exchange = recorder.record(_raw())
    assert ("path", "segment3", "8821") in exchange.resource_refs


def test_sensitive_headers_redacted_by_default(recorder: CaptureRecorder) -> None:
    exchange = recorder.record(
        _raw(request=RawMessage(headers=(("Authorization", "Bearer secret"),)))
    )
    assert ("authorization", REDACTED_PLACEHOLDER) in exchange.request.headers
    assert all("secret" not in v for _, v in exchange.request.headers)


def test_sensitive_headers_can_be_dropped() -> None:
    recorder = CaptureRecorder(
        CaptureConfig(sensitive_header_action=HeaderAction.DROP)
    )
    exchange = recorder.record(
        _raw(
            request=RawMessage(
                headers=(("Authorization", "Bearer secret"), ("x-a", "1"))
            )
        )
    )
    names = [name for name, _ in exchange.request.headers]
    assert "authorization" not in names
    assert "x-a" in names


def test_redaction_keeps_determinism_but_changes_id_vs_keep() -> None:
    raw = _raw(request=RawMessage(headers=(("Authorization", "Bearer secret"),)))
    redacting = CaptureRecorder()
    keeping = CaptureRecorder(CaptureConfig(sensitive_header_action=HeaderAction.KEEP))
    # Determinism under a fixed policy.
    assert redacting.record(raw).exchange_id == redacting.record(raw).exchange_id
    # Different policy legitimately yields a different artifact.
    assert redacting.record(raw).exchange_id != keeping.record(raw).exchange_id


def test_binary_body_is_preserved(recorder: CaptureRecorder) -> None:
    raw_bytes = b"\x89PNG\r\n\x1a\n\xff\xfe\x00\x01"
    exchange = recorder.record(
        _raw(response=RawMessage(body=raw_bytes))
    )
    assert exchange.response.body == raw_bytes


def test_record_all_preserves_order_and_count(recorder: CaptureRecorder) -> None:
    raws = [
        _raw(url="https://h.test/a/1"),
        _raw(url="https://h.test/b/2"),
    ]
    out = list(recorder.record_all(raws))
    assert len(out) == 2
    assert out[0].url == "https://h.test/a/1"
    assert out[1].url == "https://h.test/b/2"


@pytest.mark.parametrize(
    "overrides",
    [
        {"account_label": ""},
        {"method": ""},
        {"url": ""},
        {"url": "/relative/only"},
        {"status_code": 7},
        {"status_code": 999},
    ],
)
def test_record_rejects_malformed_input(
    recorder: CaptureRecorder, overrides: dict[str, object]
) -> None:
    with pytest.raises(MalformedExchangeError):
        recorder.record(_raw(**overrides))
