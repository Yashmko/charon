"""``CapturedExchange`` and supporting HTTP types.

A :class:`CapturedExchange` is an immutable, content-addressed record of one
HTTP(S) request/response pair plus metadata, captured directly from real
traffic. Its provenance is therefore always ``Observed``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from charon.model.addressing import ContentAddress, content_address
from charon.model.provenance import Provenance

__all__ = ["HttpMessage", "CapturedExchange"]


def _normalize_headers(
    headers: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    """Return headers canonicalized for deterministic content addressing.

    Header names are lower-cased and the sequence is sorted. HTTP header
    names are case-insensitive, so this keeps the content address stable
    regardless of the casing or ordering a capture tool emitted.
    """
    lowered = tuple((name.lower(), value) for name, value in headers)
    return tuple(sorted(lowered))


@dataclass(frozen=True, slots=True)
class HttpMessage:
    """An immutable HTTP message (request or response) body + headers.

    ``body`` is stored as text exactly as captured. Parsing/normalization of
    bodies is the responsibility of the (not-yet-implemented) ``compare``
    module; the model keeps the raw observation.
    """

    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _normalize_headers(self.headers))

    def to_canonical(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable view of this message."""
        return {
            "headers": [list(pair) for pair in self.headers],
            "body": self.body,
        }


@dataclass(frozen=True, slots=True)
class CapturedExchange:
    """Immutable, content-addressed record of one request/response pair.

    Provenance is always ``Observed``: the record is captured directly from
    real traffic. The :attr:`exchange_id` is derived from the canonical
    content, so identical traffic yields identical ids (architecture
    ``capture`` acceptance criteria).
    """

    account_label: str
    method: str
    url: str
    request: HttpMessage
    status_code: int
    response: HttpMessage
    #: Identifiers extracted from the request, as ``(location, name, value)``
    #: triples (e.g. ``("path", "id", "8821")``). Kept sorted for stability.
    resource_refs: tuple[tuple[str, str, str], ...] = ()
    exchange_id: ContentAddress = field(default="", compare=False)

    #: Provenance is fixed for this artifact type.
    provenance: Provenance = field(default=Provenance.OBSERVED, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "method", self.method.upper()
        )
        object.__setattr__(
            self, "resource_refs", tuple(sorted(self.resource_refs))
        )
        object.__setattr__(self, "exchange_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this exchange.

        The artifact's own id is intentionally excluded so the address is a
        pure function of observed content.
        """
        return {
            "type": "CapturedExchange",
            "account_label": self.account_label,
            "method": self.method,
            "url": self.url,
            "request": self.request.to_canonical(),
            "status_code": self.status_code,
            "response": self.response.to_canonical(),
            "resource_refs": [list(r) for r in self.resource_refs],
        }
