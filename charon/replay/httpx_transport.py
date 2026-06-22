"""Default ``httpx``-backed :class:`~charon.replay.transport.Transport`.

``httpx`` is imported lazily inside the constructor so the rest of Charon
(model, capture, and the replay abstractions) does not require ``httpx`` to
be installed. Downstream modules must depend on the
:class:`~charon.replay.transport.Transport` protocol, never on this class
directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charon.replay.errors import (
    ReplayConnectionError,
    ReplayMalformedResponseError,
    ReplayTimeoutError,
    ReplayTransportError,
)
from charon.replay.transport import TransportRequest, TransportResponse

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx

__all__ = ["HttpxTransport"]


class HttpxTransport:
    """A :class:`~charon.replay.transport.Transport` implemented with httpx.

    :param client: An optional pre-configured ``httpx.Client``. If omitted, a
        client is created lazily on first use. Supplying a client lets the
        caller control connection pooling, verification, and proxies without
        this module taking a hard dependency at import time.
    """

    def __init__(self, client: "httpx.Client | None" = None) -> None:
        self._client = client

    def _get_client(self) -> "httpx.Client":
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover - env dependent
                raise ReplayTransportError(
                    "httpx is required for HttpxTransport; install the "
                    "'replay' extra or provide a custom Transport."
                ) from exc
            self._client = httpx.Client()
        return self._client

    def send(self, request: TransportRequest) -> TransportResponse:
        """Send ``request`` via httpx, translating failures to typed errors."""
        import httpx

        client = self._get_client()
        try:
            response = client.request(
                method=request.method,
                url=request.url,
                headers=list(request.headers),
                content=request.body,
                follow_redirects=request.follow_redirects,
                timeout=request.timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise ReplayTimeoutError(str(exc)) from exc
        except httpx.ConnectError as exc:
            raise ReplayConnectionError(str(exc)) from exc
        except httpx.RemoteProtocolError as exc:
            raise ReplayMalformedResponseError(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise ReplayTransportError(str(exc)) from exc

        redirect_chain = tuple(str(r.url) for r in response.history)
        return TransportResponse(
            status_code=response.status_code,
            headers=tuple(
                (name, value) for name, value in response.headers.items()
            ),
            body=response.content,
            redirect_chain=redirect_chain,
        )

    def close(self) -> None:
        """Close the underlying client if one was created."""
        if self._client is not None:
            self._client.close()
