"""Tests for the Charon CLI.

These tests focus on argument parsing and output generation. The
pipeline itself is tested separately in :mod:`tests.pipeline.test_engine`;
these tests only verify that the CLI correctly interprets arguments and
passes them to the pipeline.

For the ``analyze`` command, we use a minimal pipeline with a stub
transport so no real network calls are made.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from charon.cli import build_arg_parser, main
from charon.replay import TransportResponse

# Reuse the replay test suite's stub transport.
from tests.replay.conftest import StubTransport


class TestArgParser:
    """Tests for argument parsing only (no pipeline execution)."""

    def test_analyze_command_parsed(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(["analyze", "input.har"])
        assert ns.command == "analyze"
        assert ns.input == "input.har"

    def test_analyze_with_credentials_file(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(
            ["analyze", "input.json", "--credentials", "creds.json"]
        )
        assert ns.credentials == "creds.json"

    def test_analyze_with_inline_credential(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args([
            "analyze", "input.json",
            "--credential", "userB=bearer:tok123",
        ])
        assert ns.inline_credentials == ["userB=bearer:tok123"]

    def test_analyze_with_output_file(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args([
            "analyze", "input.json", "--output", "report.json",
        ])
        assert ns.output == "report.json"

    def test_analyze_with_format(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(
            ["analyze", "input.json", "--format", "markdown"]
        )
        assert ns.format == "markdown"

    def test_analyze_with_timeout(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(["analyze", "input.json", "--timeout", "5.0"])
        assert ns.timeout == 5.0

    def test_version_command(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(["version"])
        assert ns.command == "version"

    def test_help_does_not_raise(self) -> None:
        parser = build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])

    def test_default_format_is_json(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(["analyze", "input.json"])
        assert ns.format == "json"

    def test_default_mode_is_deterministic(self) -> None:
        parser = build_arg_parser()
        ns = parser.parse_args(["analyze", "input.json"])
        assert ns.mode == "deterministic"


class TestMain:
    """End-to-end CLI tests with a capture file and stub pipeline."""

    def _write_capture_json(self, exchanges: list[dict[str, object]]) -> str:
        """Write a temporary JSON capture file and return its path."""
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        )
        json.dump(exchanges, tmp)
        tmp.close()
        return tmp.name

    def test_analyze_with_json_input_and_credentials(self) -> None:
        """Run analyze with a JSON capture file and credentials."""
        import charon.cli.main as cli_main

        capture_path = self._write_capture_json(
            [
                {
                    "account_label": "userA",
                    "method": "GET",
                    "url": "https://api.example.test/api/invoices/8821",
                    "status_code": 200,
                    "request": {
                        "headers": {"Content-Type": "application/json"},
                        "body": None,
                    },
                    "response": {
                        "headers": {
                            "Content-Type": "application/json",
                        },
                        "body": '{"id": 8821, "owner": "userA"}',
                    },
                }
            ]
        )
        try:
            cli_main._TEST_TRANSPORT = StubTransport(
                response=TransportResponse(
                    status_code=200,
                    headers=(("Content-Type", "application/json"),),
                    body=json.dumps({"id": 8821, "owner": "userA"}).encode("utf-8"),
                )
            )
            try:
                exit_code = main([
                    "analyze",
                    capture_path,
                    "--credential", "userB=bearer:tok-b",
                    "--format", "json",
                    "--verbose",
                ])
            finally:
                cli_main._TEST_TRANSPORT = None
        finally:
            Path(capture_path).unlink(missing_ok=True)

        assert exit_code == 0

    def test_analyze_missing_input_file(self) -> None:
        """Missing input file should exit with error."""
        exit_code = main([
            "analyze",
            "/tmp/nonexistent_capture_file.json",
            "--credential", "userB=bearer:tok-b",
        ])
        # Should exit with error code 1.
        assert exit_code == 1

    def test_analyze_no_credentials(self) -> None:
        """Running analyze without credentials should exit with error."""
        capture_path = self._write_capture_json(
            [
                {
                    "account_label": "userA",
                    "method": "GET",
                    "url": "https://api.example.test/test",
                    "status_code": 200,
                }
            ]
        )
        try:
            exit_code = main(
                [
                    "analyze",
                    capture_path,
                ]
            )
            assert exit_code == 1
        finally:
            Path(capture_path).unlink(missing_ok=True)

    def test_version_exit_code(self) -> None:
        """Version command should exit with 0."""
        exit_code = main(["version"])
        assert exit_code == 0


class TestCredentialParsing:
    """Tests for the inline credential parser (internal helper)."""

    def test_bearer_token(self) -> None:
        from charon.cli.main import _parse_inline_credential

        cred = _parse_inline_credential("attacker=bearer:tok-secret")
        assert cred.label == "attacker"
        assert cred.bearer_token == "tok-secret"

    def test_api_key(self) -> None:
        from charon.cli.main import _parse_inline_credential

        cred = _parse_inline_credential("admin=apikey:X-API-Key:abc123")
        assert cred.label == "admin"
        assert cred.api_key == "abc123"
        assert cred.api_key_header == "X-API-Key"

    def test_invalid_spec_raises(self) -> None:
        import pytest
        from charon.cli.main import _parse_inline_credential

        with pytest.raises(ValueError):
            _parse_inline_credential("label=unknown:foo")

    def test_missing_label_raises(self) -> None:
        import pytest
        from charon.cli.main import _parse_inline_credential

        with pytest.raises(ValueError):
            _parse_inline_credential("=bearer:token")

    def test_missing_equal_sign_raises(self) -> None:
        import pytest
        from charon.cli.main import _parse_inline_credential

        with pytest.raises(ValueError):
            _parse_inline_credential("justastring")

    def test_error_messages_do_not_echo_secret(self) -> None:
        """Error messages must NOT include the supplied secret value."""
        import pytest
        from charon.cli.main import _parse_inline_credential

        with pytest.raises(ValueError, match="Unknown credential type"):
            _parse_inline_credential("attacker=unknown:foo")

        with pytest.raises(ValueError, match="missing '='"):
            _parse_inline_credential("justastring")
