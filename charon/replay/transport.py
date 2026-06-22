"""Transport abstraction for the replay engine.

The engine depends only on the :class:`Transport` protocol and the plain
:class:`TransportRequest` / :class:`TransportResponse` byte-level records.
This keeps any concrete HTTP client (``httpx`` by default) an implementation
detail that downstream modules never import.

Transport implementations must raise the typed errors from
:mod:`charon.replay.errors` on failure so the engine can record them
deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = ["TransportRequest", "TransportResponse", "Transport"]


@dataclass(frozen=True, slots=True)
class TransportRequest:
    """A fully-resolved HTTP request to send, including auth material.

    This object *may* contain secrets (in ``headers``); it is transient and
    never persisted or content-addressed. Bodies are raw bytes.
    """

    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None
    #: Whether the transport should follow redirects. Kept explicit so replay
    #: behavior is a deterministic function of configuration.
    follow_redirects: bool = False
    #: Total timeout in seconds for the request.
    timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """The raw result of sending a :class:`TransportRequest`.

    Holds the final response after any redirects the transport followed.
    ``redirect_chain`` records intermediate locations so the engine can flag
    them, rather than silently hiding redirect behavior.
    """

    status_code: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None
    #: URLs of any intermediate redirect hops, in order.
    redirect_chain: tuple[str, ...] = field(default=())


@runtime_checkable
class Transport(Protocol):
    """Protocol every replay transport implements.

    Implementations must be side-effect-isolated to the network call and must
    translate client-specific failures into the typed errors in
    :mod:`charon.replay.errors`.
    """

    def send(self, request: TransportRequest) -> TransportResponse:
        """Send ``request`` and return the raw response.

        :raises charon.replay.errors.ReplayTimeoutError: on timeout.
        :raises charon.replay.errors.ReplayConnectionError: on connect
            failure.
        :raises charon.replay.errors.ReplayMalformedResponseError: if the
            response cannot be parsed.
        :raises charon.replay.errors.ReplayTransportError: on any other
            transport failure.
        """
        ...
