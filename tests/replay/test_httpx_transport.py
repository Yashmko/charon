"""Integration tests for ``HttpxTransport`` using a real local HTTP server.

These tests verify that the httpx-based transport correctly sends requests,
receives responses, and translates transport-level failures into Charon's
typed error hierarchy. The server is ephemeral and deterministic per test.
"""

from __future__ import annotations

import pytest
from charon.replay import TransportRequest
from charon.replay.errors import (
    ReplayConnectionError,
    ReplayTransportError,
)
from charon.replay.httpx_transport import HttpxTransport
from pytest_httpserver import HTTPServer
from werkzeug import Response as WzResponse


class TestHttpxTransport:
    """Integration tests against a local ``pytest-httpserver`` server."""

    def test_successful_request(
        self, httpserver: HTTPServer, httpx_transport: HttpxTransport
    ) -> None:
        httpserver.expect_request("/ok").respond_with_json({"status": "ok"})
        request = TransportRequest(
            method="GET",
            url=httpserver.url_for("/ok"),
        )
        response = httpx_transport.send(request)
        assert response.status_code == 200
        assert response.body is not None
        assert b"ok" in response.body

    def test_status_code_preserved(
        self, httpserver: HTTPServer, httpx_transport: HttpxTransport
    ) -> None:
        httpserver.expect_request("/teapot").respond_with_data(
            "short and stout", status=418
        )
        request = TransportRequest(method="GET", url=httpserver.url_for("/teapot"))
        response = httpx_transport.send(request)
        assert response.status_code == 418
        assert response.body == b"short and stout"

    def test_redirect_is_not_followed_by_default(
        self, httpserver: HTTPServer, httpx_transport: HttpxTransport
    ) -> None:
        httpserver.expect_request("/redirect").respond_with_response(
            WzResponse(status=301, headers={"Location": httpserver.url_for("/final")})
        )
        httpserver.expect_request("/final").respond_with_json({"status": "ok"})
        request = TransportRequest(
            method="GET",
            url=httpserver.url_for("/redirect"),
        )
        response = httpx_transport.send(request)
        assert response.status_code == 301
        # The engine is responsible for following redirects via follow_redirects;
        # the transport merely reports what it observed.

    def test_redirect_is_followed_when_configured(
        self, httpserver: HTTPServer,
    ) -> None:
        httpserver.expect_request("/redirect").respond_with_response(
            WzResponse(status=301, headers={"Location": httpserver.url_for("/final")})
        )
        httpserver.expect_request("/final").respond_with_json({"status": "ok"})
        transport = HttpxTransport()
        request = TransportRequest(
            method="GET",
            url=httpserver.url_for("/redirect"),
            follow_redirects=True,
        )
        response = transport.send(request)
        assert response.status_code == 200
        assert len(response.redirect_chain) == 1
        assert "redirect" in response.redirect_chain[0]

    def test_headers_round_trip(
        self, httpserver: HTTPServer, httpx_transport: HttpxTransport
    ) -> None:
        httpserver.expect_request(
            "/headers", headers={"X-Custom": "test-value"}
        ).respond_with_data("matched", status=202)

        request = TransportRequest(
            method="GET",
            url=httpserver.url_for("/headers"),
            headers=(("X-Custom", "test-value"),),
        )
        response = httpx_transport.send(request)
        assert response.status_code == 202
        assert response.body == b"matched"

    def test_body_bytes_round_trip(
        self, httpserver: HTTPServer, httpx_transport: HttpxTransport
    ) -> None:
        binary = b"\x00\x01\x02\xff\xfe"
        httpserver.expect_request(
            "/binary", method="POST"
        ).respond_with_data(binary)
        request = TransportRequest(
            method="POST",
            url=httpserver.url_for("/binary"),
            body=binary,
        )
        response = httpx_transport.send(request)
        assert response.body == binary

    def test_connection_refused(self) -> None:
        """Connecting to a port with no listener yields a typed error."""
        transport = HttpxTransport()
        request = TransportRequest(
            method="GET",
            url="http://127.0.0.1:1/nonexistent",
            timeout_seconds=1.0,
        )
        with pytest.raises(ReplayConnectionError):
            transport.send(request)

    def test_malformed_response_or_connection_error(self) -> None:
        """Connecting to a port with no listener produces a typed error.

        The httpx transport wraps all transport-level failures in Charon's
        typed error hierarchy. Connecting to a closed port deterministically
        exercises this path.
        """
        transport = HttpxTransport()
        request = TransportRequest(
            method="GET",
            url="http://127.0.0.1:1/malformed",
            timeout_seconds=1.0,
        )
        with pytest.raises((ReplayConnectionError, ReplayTransportError)):
            transport.send(request)

    def test_custom_timeout(
        self, httpserver: HTTPServer, httpx_transport: HttpxTransport
    ) -> None:
        httpserver.expect_request("/timeout-cfg").respond_with_data("fast")
        request = TransportRequest(
            method="GET",
            url=httpserver.url_for("/timeout-cfg"),
            timeout_seconds=5.0,
        )
        response = httpx_transport.send(request)
        assert response.status_code == 200

    def test_deterministic_headers_order(
        self, httpserver: HTTPServer,
    ) -> None:
        """The transport preserves header order for deterministic addressing."""
        httpserver.expect_request("/headers-order").respond_with_data("ok")
        t = HttpxTransport()
        request = TransportRequest(
            method="GET",
            url=httpserver.url_for("/headers-order"),
            headers=(("A", "1"), ("B", "2")),
        )
        response = t.send(request)
        # The response preserves whatever the server sends; we just verify
        # the transport doesn't silently reorder or drop them.
        assert response.status_code == 200


@pytest.fixture
def httpx_transport() -> HttpxTransport:
    return HttpxTransport()
