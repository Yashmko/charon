"""Tests for the capture backends and the backend abstraction."""

from __future__ import annotations

import base64

import pytest
from charon.capture import (
    CaptureBackend,
    CaptureRecorder,
    HarCaptureBackend,
    MalformedExchangeError,
    RawDictCaptureBackend,
    RawExchange,
)


def test_raw_dict_backend_satisfies_protocol() -> None:
    backend = RawDictCaptureBackend([])
    assert isinstance(backend, CaptureBackend)


def test_raw_dict_backend_yields_raw_exchanges() -> None:
    backend = RawDictCaptureBackend(
        [
            {
                "account_label": "userA",
                "method": "GET",
                "url": "https://h.test/orders/1",
                "status_code": 200,
                "request": {"headers": {"X-A": "1"}, "body": None},
                "response": {
                "headers": {"Content-Type": "application/json"},
                "body": b"{}",
            },
            }
        ]
    )
    exchanges = list(backend.exchanges())
    assert len(exchanges) == 1
    assert isinstance(exchanges[0], RawExchange)
    assert exchanges[0].response.body == b"{}"


def test_raw_dict_backend_str_body_becomes_utf8() -> None:
    backend = RawDictCaptureBackend(
        [
            {
                "account_label": "userA",
                "method": "POST",
                "url": "https://h.test/x",
                "status_code": 201,
                "request": {"body": "hello"},
            }
        ]
    )
    (exchange,) = list(backend.exchanges())
    assert exchange.request.body == b"hello"


def test_raw_dict_backend_rejects_missing_fields() -> None:
    backend = RawDictCaptureBackend([{"method": "GET"}])
    with pytest.raises(MalformedExchangeError):
        list(backend.exchanges())


def test_raw_dict_backend_rejects_bad_body_type() -> None:
    backend = RawDictCaptureBackend(
        [
            {
                "account_label": "userA",
                "method": "GET",
                "url": "https://h.test/x",
                "status_code": 200,
                "request": {"body": 12345},
            }
        ]
    )
    with pytest.raises(MalformedExchangeError):
        list(backend.exchanges())


def _har(
    *, body_text: str | None = None, encoding: str | None = None
) -> dict[str, object]:
    content: dict[str, object] = {}
    if body_text is not None:
        content["text"] = body_text
    if encoding is not None:
        content["encoding"] = encoding
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/orders/8821",
                        "headers": [{"name": "X-A", "value": "1"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "content": content,
                    },
                }
            ]
        }
    }


def test_har_backend_parses_entry() -> None:
    backend = HarCaptureBackend(_har(body_text="{}"), account_label="userA")
    (exchange,) = list(backend.exchanges())
    assert exchange.account_label == "userA"
    assert exchange.method == "GET"
    assert exchange.status_code == 200
    assert exchange.response.body == b"{}"


def test_har_backend_decodes_base64_body() -> None:
    raw = b"\x00\x01\x02binary"
    har = _har(body_text=base64.b64encode(raw).decode("ascii"), encoding="base64")
    backend = HarCaptureBackend(har, account_label="userA")
    (exchange,) = list(backend.exchanges())
    assert exchange.response.body == raw


def test_har_backend_rejects_bad_base64() -> None:
    har = _har(body_text="!!!not-base64!!!", encoding="base64")
    backend = HarCaptureBackend(har, account_label="userA")
    with pytest.raises(MalformedExchangeError):
        list(backend.exchanges())


def test_har_backend_rejects_missing_log() -> None:
    backend = HarCaptureBackend({}, account_label="userA")
    with pytest.raises(MalformedExchangeError):
        list(backend.exchanges())


def test_backend_to_recorder_end_to_end_is_deterministic() -> None:
    recorder = CaptureRecorder()
    backend = HarCaptureBackend(_har(body_text="{}"), account_label="userA")
    first = [e.exchange_id for e in recorder.record_all(backend.exchanges())]
    backend2 = HarCaptureBackend(_har(body_text="{}"), account_label="userA")
    second = [e.exchange_id for e in recorder.record_all(backend2.exchanges())]
    assert first == second
