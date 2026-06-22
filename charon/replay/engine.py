"""The replay engine: faithfully re-issue captured exchanges.

The :class:`ReplayEngine` is the single public entry point. It:

#. Derives a deterministic, secret-free
   :class:`~charon.model.ReplayRequest` from a
   :class:`~charon.model.CapturedExchange` and a runtime
   :class:`~charon.replay.credential.ReplayCredential`.
#. Sends the request via an injected
   :class:`~charon.replay.transport.Transport`.
#. Records the outcome as a :class:`~charon.replay.result.ReplayExecution`
   (a model ``ReplayResult`` on success, or a typed ``ReplayFailure`` on a
   transport error), preserving raw bytes and flagging redirects as
   nondeterminism notes.

The engine performs no comparison, detection, or analysis; it only replays
and records.
"""

from __future__ import annotations

from charon.model import (
    CapturedExchange,
    HttpMessage,
    ReplayRequest,
    ReplayResult,
)
from charon.replay.credential import (
    REDACTED_PLACEHOLDER,
    SENSITIVE_HEADERS,
    ReplayCredential,
)
from charon.replay.errors import (
    ReplayConnectionError,
    ReplayMalformedResponseError,
    ReplayTimeoutError,
    ReplayTransportError,
)
from charon.replay.result import (
    ReplayExecution,
    ReplayFailure,
    ReplayFailureKind,
)
from charon.replay.transport import (
    Transport,
    TransportRequest,
    TransportResponse,
)

__all__ = ["ReplayEngine"]


def _merge_headers(
    base: tuple[tuple[str, str], ...],
    overrides: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    """Merge ``overrides`` onto ``base`` by (lower-cased) header name.

    Headers present in ``overrides`` replace any same-named header in
    ``base``; this is how auth material is substituted without disturbing
    unrelated request structure. Non-overridden headers keep their original
    relative order; overrides are appended in their given order.
    """
    override_names = {name.lower() for name, _ in overrides}
    merged: list[tuple[str, str]] = [
        (name, value)
        for name, value in base
        if name.lower() not in override_names
    ]
    merged.extend(overrides)
    return tuple(merged)


def _redact(
    headers: tuple[tuple[str, str], ...],
    applied_auth_names: frozenset[str],
) -> tuple[tuple[str, str], ...]:
    """Redact sensitive header values for the persisted artifact.

    A header value is redacted if its (lower-cased) name is a known sensitive
    header or was set by the credential. Names are preserved so request
    structure stays comparable; only secret *values* are removed. The result
    is sorted for a deterministic content address.
    """
    redacted: list[tuple[str, str]] = []
    for name, value in headers:
        lname = name.lower()
        if lname in SENSITIVE_HEADERS or lname in applied_auth_names:
            redacted.append((lname, REDACTED_PLACEHOLDER))
        else:
            redacted.append((lname, value))
    return tuple(sorted(redacted))


class ReplayEngine:
    """Re-issues captured exchanges under a configurable identity.

    :param transport: The transport used to send requests. Any object
        satisfying the :class:`~charon.replay.transport.Transport` protocol.
    :param follow_redirects: Whether the transport should follow redirects.
        Fixed per engine so replay is a deterministic function of config.
    :param timeout_seconds: Per-request timeout passed to the transport.
    """

    def __init__(
        self,
        transport: Transport,
        *,
        follow_redirects: bool = False,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._transport = transport
        self._follow_redirects = follow_redirects
        self._timeout_seconds = timeout_seconds

    def build_request(
        self,
        exchange: CapturedExchange,
        credential: ReplayCredential,
    ) -> ReplayRequest:
        """Build the secret-free, content-addressed ``ReplayRequest``.

        The captured request headers have the credential's auth headers
        substituted in, then all sensitive values are redacted before the
        artifact is addressed. Method and URL are taken from the (already
        normalized) captured exchange.
        """
        merged = _merge_headers(
            exchange.request.headers, credential.auth_headers()
        )
        persisted_headers = _redact(merged, credential.applied_header_names())
        persisted_request = HttpMessage(
            headers=persisted_headers, body=exchange.request.body
        )
        return ReplayRequest(
            source_exchange_id=exchange.exchange_id,
            identity=credential.identity,
            method=exchange.method,
            url=exchange.url,
            request=persisted_request,
        )

    def _transport_request(
        self,
        exchange: CapturedExchange,
        credential: ReplayCredential,
    ) -> TransportRequest:
        """Build the transient outgoing request, including real secrets."""
        merged = _merge_headers(
            exchange.request.headers, credential.auth_headers()
        )
        return TransportRequest(
            method=exchange.method,
            url=exchange.url,
            headers=merged,
            body=exchange.request.body,
            follow_redirects=self._follow_redirects,
            timeout_seconds=self._timeout_seconds,
        )

    @staticmethod
    def _result_from_response(
        replay_request: ReplayRequest,
        baseline_exchange_id: str,
        response: TransportResponse,
    ) -> ReplayResult:
        notes: list[str] = []
        if response.redirect_chain:
            hops = " -> ".join(response.redirect_chain)
            notes.append(f"redirect-chain: {hops}")
        message = HttpMessage(
            headers=tuple(
                (name.lower(), value) for name, value in response.headers
            ),
            body=response.body,
        )
        return ReplayResult(
            replay_request_id=replay_request.request_id,
            baseline_exchange_id=baseline_exchange_id,
            status_code=response.status_code,
            response=message,
            nondeterminism_notes=tuple(notes),
        )

    def replay(
        self,
        exchange: CapturedExchange,
        credential: ReplayCredential,
    ) -> ReplayExecution:
        """Replay ``exchange`` under ``credential`` and record the outcome.

        Returns a :class:`ReplayExecution` wrapping either a model
        ``ReplayResult`` (a real HTTP response was received) or a typed
        ``ReplayFailure`` (transport error). Never raises for ordinary
        transport failures; raises only on programmer error.
        """
        replay_request = self.build_request(exchange, credential)
        transport_request = self._transport_request(exchange, credential)

        try:
            response = self._transport.send(transport_request)
        except ReplayTimeoutError as exc:
            return self._fail(replay_request, ReplayFailureKind.TIMEOUT, exc)
        except ReplayConnectionError as exc:
            return self._fail(replay_request, ReplayFailureKind.CONNECTION, exc)
        except ReplayMalformedResponseError as exc:
            return self._fail(
                replay_request, ReplayFailureKind.MALFORMED_RESPONSE, exc
            )
        except ReplayTransportError as exc:
            return self._fail(replay_request, ReplayFailureKind.TRANSPORT, exc)

        result = self._result_from_response(
            replay_request, exchange.exchange_id, response
        )
        return ReplayExecution(request=replay_request, result=result)

    @staticmethod
    def _fail(
        replay_request: ReplayRequest,
        kind: ReplayFailureKind,
        exc: Exception,
    ) -> ReplayExecution:
        failure = ReplayFailure(
            replay_request=replay_request, kind=kind, detail=str(exc)
        )
        return ReplayExecution(request=replay_request, failure=failure)
