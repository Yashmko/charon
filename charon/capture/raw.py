"""Backend-agnostic intermediate representation of a captured exchange.

Every capture backend converts its source format into these plain, untyped-
at-the-edges structures. A single normalization/conversion path
(:mod:`charon.capture.recorder`) then turns a :class:`RawExchange` into a
deterministic :class:`~charon.model.CapturedExchange`. Keeping this seam
means new backends never change downstream code.

These types intentionally hold *raw* observation only: headers as captured
(order and casing preserved for the backend's benefit), body as raw bytes,
and no derived/normalized fields. Normalization is applied later so it is
applied identically regardless of source.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["RawMessage", "RawExchange"]


@dataclass(frozen=True, slots=True)
class RawMessage:
    """Raw, backend-agnostic view of one HTTP message (request or response).

    :param headers: Header name/value pairs exactly as the backend produced
        them. Casing and ordering are preserved here; normalization happens
        downstream.
    :param body: Raw body bytes, or ``None`` when absent.
    """

    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None


@dataclass(frozen=True, slots=True)
class RawExchange:
    """Raw, backend-agnostic view of one request/response pair.

    :param account_label: Which capture identity produced the request
        (e.g. ``"userA"``). Part of the deterministic artifact because the
        owning identity is meaningful signal, not a secret.
    :param method: HTTP method as captured (normalized downstream).
    :param url: Absolute request URL as captured (normalized downstream).
    :param request: The request message.
    :param status_code: Response status code.
    :param response: The response message.
    """

    account_label: str
    method: str
    url: str
    status_code: int
    request: RawMessage = field(default_factory=RawMessage)
    response: RawMessage = field(default_factory=RawMessage)
