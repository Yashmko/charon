"""Convert backend-agnostic raw exchanges into deterministic artifacts.

The :class:`CaptureRecorder` is the single normalization/conversion path: it
takes a :class:`~charon.capture.raw.RawExchange` from any backend and emits an
immutable, content-addressed :class:`~charon.model.CapturedExchange`. Because
all backends funnel through here, the determinism and secret-handling rules
live in exactly one place.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from urllib.parse import urlsplit

from charon.capture.config import (
    REDACTED_PLACEHOLDER,
    CaptureConfig,
    HeaderAction,
)
from charon.capture.errors import MalformedExchangeError
from charon.capture.normalize import (
    extract_resource_refs,
    normalize_headers,
    normalize_method,
    normalize_query,
    normalize_url,
)
from charon.capture.raw import RawExchange, RawMessage
from charon.model import CapturedExchange, HttpMessage

__all__ = ["CaptureRecorder"]


def _content_type(headers: tuple[tuple[str, str], ...]) -> str | None:
    """Return the (lower-cased) content-type header value, if present."""
    for name, value in headers:
        if name == "content-type":
            return value
    return None


class CaptureRecorder:
    """Builds deterministic ``CapturedExchange`` records from raw input.

    :param config: Runtime capture configuration (secret handling). Not part
        of the content-addressed artifact. Defaults to a config that redacts
        common credential-bearing headers.
    """

    def __init__(self, config: CaptureConfig | None = None) -> None:
        self._config = config if config is not None else CaptureConfig()

    @property
    def config(self) -> CaptureConfig:
        """The recorder's runtime configuration."""
        return self._config

    def _apply_secret_policy(
        self, headers: tuple[tuple[str, str], ...]
    ) -> tuple[tuple[str, str], ...]:
        """Apply the configured sensitive-header policy.

        Runs on already-normalized (lower-cased, sorted) headers so behavior
        is deterministic. Secrets are removed/redacted *before* the artifact
        is content-addressed, keeping credentials out of persisted records.
        """
        action = self._config.sensitive_header_action
        result: list[tuple[str, str]] = []
        for name, value in headers:
            if not self._config.is_sensitive(name) or action is HeaderAction.KEEP:
                result.append((name, value))
            elif action is HeaderAction.REDACT:
                result.append((name, REDACTED_PLACEHOLDER))
            elif action is HeaderAction.DROP:
                continue
        return tuple(result)

    def _build_message(
        self, raw: RawMessage
    ) -> tuple[HttpMessage, tuple[tuple[str, str], ...]]:
        """Normalize a raw message into an ``HttpMessage`` + clean headers.

        Returns both the model message (with the secret policy applied) and
        the normalized headers *before* the policy, so the caller can read
        the content-type for resource extraction.
        """
        normalized = normalize_headers(raw.headers)
        policy_headers = self._apply_secret_policy(normalized)
        message = HttpMessage(headers=policy_headers, body=raw.body)
        return message, normalized

    def record(self, raw: RawExchange) -> CapturedExchange:
        """Convert a single :class:`RawExchange` into a ``CapturedExchange``.

        :raises MalformedExchangeError: if the raw exchange is missing the
            data needed to form a valid, addressable record.
        """
        self._validate(raw)

        method = normalize_method(raw.method)
        url = normalize_url(raw.url)

        request_message, request_headers = self._build_message(raw.request)
        response_message, _ = self._build_message(raw.response)

        split = urlsplit(url)
        resource_refs = extract_resource_refs(
            path=split.path,
            query=normalize_query(split.query),
            body=raw.request.body,
            content_type=_content_type(request_headers),
        )

        return CapturedExchange(
            account_label=raw.account_label,
            method=method,
            url=url,
            request=request_message,
            status_code=raw.status_code,
            response=response_message,
            resource_refs=resource_refs,
        )

    def record_all(self, raws: Iterable[RawExchange]) -> Iterator[CapturedExchange]:
        """Convert many raw exchanges, yielding one record each.

        Order is preserved; deduplication is intentionally *not* performed
        here (identical traffic legitimately produces identical ids, and
        callers decide how to handle repeats).
        """
        for raw in raws:
            yield self.record(raw)

    @staticmethod
    def _validate(raw: RawExchange) -> None:
        if not raw.account_label:
            raise MalformedExchangeError("RawExchange requires an account_label.")
        if not raw.method or not raw.method.strip():
            raise MalformedExchangeError("RawExchange requires an HTTP method.")
        if not raw.url or not raw.url.strip():
            raise MalformedExchangeError("RawExchange requires a URL.")
        split = urlsplit(raw.url.strip())
        if not split.scheme or not split.netloc:
            raise MalformedExchangeError(
                f"RawExchange URL must be absolute (scheme + host); got {raw.url!r}."
            )
        if not isinstance(raw.status_code, int) or not 100 <= raw.status_code <= 599:
            raise MalformedExchangeError(
                f"RawExchange status_code must be a valid HTTP code; got "
                f"{raw.status_code!r}."
            )
