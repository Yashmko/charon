"""Capture backends: pluggable sources that yield ``RawExchange`` objects.

A backend's sole job is to translate some source format (HAR, a raw dict,
and -- later -- Burp/mitmproxy exports) into the backend-agnostic
:class:`~charon.capture.raw.RawExchange`. All normalization, determinism, and
secret handling happen downstream in
:class:`~charon.capture.recorder.CaptureRecorder`, so adding a backend never
requires touching downstream code.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from charon.capture.errors import MalformedExchangeError
from charon.capture.raw import RawExchange, RawMessage

__all__ = [
    "CaptureBackend",
    "RawDictCaptureBackend",
    "HarCaptureBackend",
]


@runtime_checkable
class CaptureBackend(Protocol):
    """Protocol every capture backend implements.

    A backend reads its source and yields backend-agnostic raw exchanges.
    Implementations must be deterministic with respect to their input: the
    same source yields the same sequence of ``RawExchange`` objects.
    """

    def exchanges(self) -> Iterator[RawExchange]:
        """Yield each captured exchange from the backend's source."""
        ...


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MalformedExchangeError(message)


def _headers_from_mapping(
    headers: Mapping[str, str] | Sequence[tuple[str, str]] | None,
) -> tuple[tuple[str, str], ...]:
    """Coerce a header mapping or pair-sequence into a tuple of pairs."""
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        return tuple((str(k), str(v)) for k, v in headers.items())
    return tuple((str(k), str(v)) for k, v in headers)


def _coerce_body(body: object) -> bytes | None:
    """Coerce a backend-provided body into raw bytes (or ``None``).

    Accepts ``bytes``/``bytearray`` directly and ``str`` as UTF-8 text. Any
    other type is rejected as malformed.
    """
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise MalformedExchangeError(
        f"Body must be bytes, str, or None; got {type(body).__name__}."
    )


class RawDictCaptureBackend:
    """Backend over an in-memory sequence of plain dictionaries.

    Useful for tests, programmatic capture, and as the simplest reference
    implementation of the :class:`CaptureBackend` protocol. Each dict has the
    shape::

        {
            "account_label": "userA",
            "method": "GET",
            "url": "https://api.example.test/orders/8821",
            "status_code": 200,
            "request": {"headers": {...}, "body": b"..." | "..." | None},
            "response": {"headers": {...}, "body": ...},
        }

    ``request``/``response`` (and their ``headers``/``body``) are optional.
    """

    def __init__(self, records: Iterable[Mapping[str, Any]]) -> None:
        self._records = list(records)

    @staticmethod
    def _message(blob: Mapping[str, Any] | None) -> RawMessage:
        if blob is None:
            return RawMessage()
        return RawMessage(
            headers=_headers_from_mapping(blob.get("headers")),
            body=_coerce_body(blob.get("body")),
        )

    def exchanges(self) -> Iterator[RawExchange]:
        for record in self._records:
            _require("method" in record, "record missing 'method'.")
            _require("url" in record, "record missing 'url'.")
            _require("status_code" in record, "record missing 'status_code'.")
            _require("account_label" in record, "record missing 'account_label'.")
            yield RawExchange(
                account_label=str(record["account_label"]),
                method=str(record["method"]),
                url=str(record["url"]),
                status_code=int(record["status_code"]),
                request=self._message(record.get("request")),
                response=self._message(record.get("response")),
            )


class HarCaptureBackend:
    """Backend over a parsed HAR (HTTP Archive) document.

    Accepts an already-parsed HAR object (a ``dict`` matching the HAR 1.2
    schema). Parsing JSON from disk is left to the caller so this backend
    has no I/O and stays trivially testable and deterministic.

    Only the request/response fields Charon needs are read; unknown HAR
    fields are ignored. The ``account_label`` is supplied by the caller
    because HAR has no native concept of a test identity.
    """

    def __init__(self, har: Mapping[str, Any], *, account_label: str) -> None:
        self._har = har
        self._account_label = account_label

    @staticmethod
    def _har_headers(
        entries: Sequence[Mapping[str, Any]] | None,
    ) -> tuple[tuple[str, str], ...]:
        if not entries:
            return ()
        return tuple(
            (str(h["name"]), str(h.get("value", "")))
            for h in entries
            if "name" in h
        )

    @staticmethod
    def _har_body(content: Mapping[str, Any] | None) -> bytes | None:
        """Extract the body bytes from a HAR ``postData``/``content`` object."""
        if not content:
            return None
        text = content.get("text")
        if text is None:
            return None
        if content.get("encoding") == "base64":
            try:
                return base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise MalformedExchangeError(
                    "HAR body declared base64 but failed to decode."
                ) from exc
        return str(text).encode("utf-8")

    def exchanges(self) -> Iterator[RawExchange]:
        log = self._har.get("log")
        _require(isinstance(log, Mapping), "HAR document missing 'log' object.")
        assert isinstance(log, Mapping)  # narrow for type-checkers
        entries = log.get("entries")
        _require(isinstance(entries, Sequence), "HAR 'log.entries' must be a list.")
        assert isinstance(entries, Sequence)

        for entry in entries:
            _require(isinstance(entry, Mapping), "HAR entry must be an object.")
            request = entry.get("request")
            response = entry.get("response")
            _require(isinstance(request, Mapping), "HAR entry missing 'request'.")
            _require(isinstance(response, Mapping), "HAR entry missing 'response'.")
            assert isinstance(request, Mapping)
            assert isinstance(response, Mapping)

            _require("method" in request, "HAR request missing 'method'.")
            _require("url" in request, "HAR request missing 'url'.")
            _require("status" in response, "HAR response missing 'status'.")

            yield RawExchange(
                account_label=self._account_label,
                method=str(request["method"]),
                url=str(request["url"]),
                status_code=int(response["status"]),
                request=RawMessage(
                    headers=self._har_headers(request.get("headers")),
                    body=self._har_body(request.get("postData")),
                ),
                response=RawMessage(
                    headers=self._har_headers(response.get("headers")),
                    body=self._har_body(response.get("content")),
                ),
            )
