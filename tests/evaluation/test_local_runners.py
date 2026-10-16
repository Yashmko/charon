from __future__ import annotations

import runpy
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNERS = [
    pytest.param(REPO_ROOT / "docs/evaluation/run_eval.py", id="vampi"),
    pytest.param(
        REPO_ROOT / "docs/evaluation/run_second_api_eval.py", id="second-api"
    ),
]


def _start_server(
    handler: type[BaseHTTPRequestHandler],
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _runner_namespace(path: Path) -> dict[str, Any]:
    return runpy.run_path(str(path))


@pytest.mark.parametrize("runner_path", RUNNERS)
def test_localhost_redirect_to_external_destination_is_blocked(
    runner_path: Path,
) -> None:
    external_requests: list[tuple[str, str | None]] = []

    class ExternalHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            external_requests.append((self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    external, external_thread = _start_server(ExternalHandler)

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://external.test:{external.server_port}/capture",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    redirect, redirect_thread = _start_server(RedirectHandler)
    original_getaddrinfo = socket.getaddrinfo

    def resolve_external(
        host: str | bytes,
        port: int | str | None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        if host == "external.test":
            host = "127.0.0.1"
        return original_getaddrinfo(host, port, *args, **kwargs)

    try:
        namespace = _runner_namespace(runner_path)
        with patch("socket.getaddrinfo", side_effect=resolve_external):
            observation = namespace["_request"](
                f"http://localhost:{redirect.server_port}",
                "GET",
                "/private",
                token="test-secret-token",
                timeout=2,
            )
        assert observation.status_code == 302
        assert external_requests == []
    finally:
        _stop_server(redirect, redirect_thread)
        _stop_server(external, external_thread)


@pytest.mark.parametrize("runner_path", RUNNERS)
def test_same_origin_localhost_redirect_remains_supported(runner_path: Path) -> None:
    class LocalHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/start":
                self.send_response(302)
                self.send_header(
                    "Location",
                    "http://localhost:"
                    f"{cast(ThreadingHTTPServer, self.server).server_port}/final",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b"local-ok")

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    server, thread = _start_server(LocalHandler)
    try:
        namespace = _runner_namespace(runner_path)
        observation = namespace["_request"](
            f"http://localhost:{server.server_port}",
            "GET",
            "/start",
            timeout=2,
        )
        assert observation.status_code == 200
        assert observation.body == b"local-ok"
    finally:
        _stop_server(server, thread)


@pytest.mark.parametrize("runner_path", RUNNERS)
def test_runner_refuses_nonempty_output_directory_without_overwriting(
    runner_path: Path, tmp_path: Path
) -> None:
    output_dir = tmp_path / "raw-results"
    output_dir.mkdir()
    report_path = output_dir / "charon-report.json"
    report_path.write_text("preserve this raw report\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="Refusing to overwrite"):
        _runner_namespace(runner_path)["_prepare_output_dir"](output_dir)

    assert report_path.read_text(encoding="utf-8") == "preserve this raw report\n"


@pytest.mark.parametrize("runner_path", RUNNERS)
def test_runner_creates_a_new_empty_output_directory(
    runner_path: Path, tmp_path: Path
) -> None:
    output_dir = tmp_path / "new-run"

    prepared = _runner_namespace(runner_path)["_prepare_output_dir"](output_dir)

    assert prepared == output_dir
    assert list(output_dir.iterdir()) == []
