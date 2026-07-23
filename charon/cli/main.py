"""Command-line interface for Charon.

Usage::

    charon analyze <input> [options]

    positional arguments:
      input                   Capture file (.har or .json)

    options:
      --credentials FILE      Credentials JSON file
      --credential SPEC       Inline credential (e.g. "label=bearer:token")
      --output FILE           Output file (default: stdout)
      --format FORMAT         Output format: json, markdown, both (default: json)
      --mode MODE             Report mode: deterministic (default)
      --timeout SECONDS       Per-request timeout (default: 30)
      --verbose, -v           Verbose output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from charon.capture import (
    CaptureRecorder,
    HarCaptureBackend,
    RawDictCaptureBackend,
)
from charon.model import CapturedExchange
from charon.pipeline import Pipeline, PipelineConfig
from charon.pipeline.engine import PipelineResult
from charon.replay import ReplayCredential
from charon.replay import Transport as TransportProtocol
from charon.report import ReportMode, render_json, render_markdown

__all__ = ["build_arg_parser", "main"]


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``charon`` CLI.

    Exposed separately so tests can validate argument parsing without
    triggering any pipeline execution.
    """
    parser = argparse.ArgumentParser(
        prog="charon",
        description="Deterministic, evidence-driven authorization analysis.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ``charon analyze`` - run the full pipeline
    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze captured traffic for authorization issues.",
        description=(
            "Run the full Charon pipeline: capture, replay, compare, detect, report. "
            "Requires a capture file (HAR or JSON) and at least one replay credential."
        ),
    )
    analyze.add_argument(
        "input",
        type=str,
        help="Capture file (.har for HTTP Archive, .json for array of exchange dicts).",
    )
    analyze.add_argument(
        "--credentials",
        type=str,
        metavar="FILE",
        help=(
            "Path to a JSON file containing an array of credential objects. "
            "Each object has a 'label' and one of: 'bearer_token', 'api_key', "
            "'cookies' (array of {name, value} objects), 'extra_headers' "
            "(array of {name, value} objects). "
            "[Recommended for production use; avoids secret exposure via "
            "shell history or process listings.]"
        ),
    )
    analyze.add_argument(
        "--credential",
        type=str,
        action="append",
        metavar="SPEC",
        dest="inline_credentials",
        help=(
            "Inline credential specification. Repeatable. "
            "Formats: 'label=bearer:TOKEN', 'label=apikey:HEADER_NAME:VALUE'. "
            "[Intended for local/testing use only. Inline secrets may be "
            "exposed through shell history or process listings. Prefer "
            "--credentials FILE for production use.]"
        ),
    )
    analyze.add_argument(
        "--output",
        "-o",
        type=str,
        metavar="FILE",
        help="Write report to FILE instead of stdout.",
    )
    analyze.add_argument(
        "--format",
        "-f",
        type=str,
        choices=["json", "markdown", "both"],
        default="json",
        help="Output format (default: json).",
    )
    analyze.add_argument(
        "--mode",
        type=str,
        choices=["deterministic", "enriched"],
        default="deterministic",
        help="Report mode (default: deterministic).",
    )
    analyze.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Per-request timeout in seconds (default: 30.0).",
    )
    analyze.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print progress information to stderr.",
    )

    # ``charon version`` - print version
    subparsers.add_parser("version", help="Print version and exit.")

    return parser


def _parse_inline_credential(spec: str) -> ReplayCredential:
    """Parse an inline credential spec into a ``ReplayCredential``.

    Supported formats:

    * ``label=bearer:TOKEN``
    * ``label=apikey:HEADER_NAME:VALUE``
    """
    _MISSING_EQUAL = ValueError(
        "Invalid credential spec: missing '=' separator. "
        "Use format 'label=bearer:TOKEN' or 'label=apikey:HEADER_NAME:VALUE'."
    )
    _EMPTY_LABEL = ValueError(
        "Invalid credential spec: label is empty. "
        "Use format 'label=bearer:TOKEN' or 'label=apikey:HEADER_NAME:VALUE'."
    )

    if "=" not in spec:
        raise _MISSING_EQUAL
    label, rest = spec.split("=", 1)
    if not label:
        raise _EMPTY_LABEL

    if rest.startswith("bearer:"):
        token = rest[len("bearer:"):]
        return ReplayCredential(label=label, bearer_token=token)

    if rest.startswith("apikey:"):
        parts = rest[len("apikey:"):].split(":", 1)
        if len(parts) != 2:
            raise ValueError(
                "Invalid api-key credential spec: must be "
                "'label=apikey:HEADER_NAME:VALUE'."
            )
        return ReplayCredential(
            label=label,
            api_key=parts[1],
            api_key_header=parts[0],
        )

    raise ValueError(
        "Unknown credential type. Use 'bearer:TOKEN' or "
        "'apikey:HEADER_NAME:VALUE'."
    )


def _load_credentials(args: argparse.Namespace) -> list[ReplayCredential]:
    """Load credentials from ``--credentials`` file and/or ``--credential`` specs.

    Returns a list of ``ReplayCredential`` objects, preserving the order
    they were specified.
    """
    credentials: list[ReplayCredential] = []

    if args.credentials:
        path = Path(args.credentials)
        if not path.exists():
            raise FileNotFoundError(f"Credentials file not found: {path}")
        raw: list[dict[str, Any]] = json.loads(path.read_text("utf-8"))
        for entry in raw:
            label = entry.get("label", "")
            if not label:
                raise ValueError("Each credential entry must have a 'label'.")
            credentials.append(
                ReplayCredential(
                    label=label,
                    bearer_token=entry.get("bearer_token"),
                    cookies=tuple(
                        (c["name"], c["value"])
                        for c in entry.get("cookies", [])
                    ),
                    api_key=entry.get("api_key"),
                    api_key_header=entry.get("api_key_header", "X-API-Key"),
                    extra_headers=tuple(
                        (h["name"], h["value"])
                        for h in entry.get("extra_headers", [])
                    ),
                )
            )

    if args.inline_credentials:
        for spec in args.inline_credentials:
            credentials.append(_parse_inline_credential(spec))

    return credentials


def _load_captures(input_path: str) -> list[dict[str, Any]]:
    """Load capture data from a file.

    Detects format by extension: ``.har`` for HAR archives, ``.json`` for
    an array of exchange dictionaries.
    """
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Capture file not found: {path}")
    raw_text = path.read_text("utf-8")

    if path.suffix.lower() == ".har":
        har: dict[str, Any] = json.loads(raw_text)
        return [har]  # Pass the full HAR dict to the backend

    parsed: list[dict[str, Any]] = json.loads(raw_text)
    return parsed


def main(
    argv: list[str] | None = None,
    transport: TransportProtocol | None = None,
) -> int:
    """Main entry point for the Charon CLI.

    :param argv: Command-line arguments (defaults to ``sys.argv[1:]``).
    :param transport: Optional transport for replay. When omitted, resolves
        ``HttpxTransport`` if ``httpx`` is available, or raises at pipeline
        time. Tests pass a stub transport here to avoid real network calls.
    :returns: Exit code (0 for success, 1 for errors).
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        import charon

        print(f"charon {charon.__version__}")
        return 0

    if args.command != "analyze":
        parser.print_help()
        return 1

    # -- Load capture inputs --
    try:
        raw_captures = _load_captures(args.input)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Error loading capture file: {exc}", file=sys.stderr)
        return 1

    # -- Parse captures into CapturedExchanges --
    recorder = CaptureRecorder()
    input_path = Path(args.input)
    if input_path.suffix.lower() == ".har":
        exchanges: list[CapturedExchange] = []
        for har_data in raw_captures:
            backend = HarCaptureBackend(har_data, account_label="captured")
            exchanges.extend(recorder.record_all(backend.exchanges()))
    else:
        exchanges = list(
            recorder.record_all(
                RawDictCaptureBackend(raw_captures).exchanges()
            )
        )

    if not exchanges:
        print("No exchanges loaded from capture file.", file=sys.stderr)
        return 1

    if args.verbose:
        print(
            f"Loaded {len(exchanges)} exchange(s).",
            file=sys.stderr,
        )

    # -- Load credentials --
    try:
        credentials = _load_credentials(args)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error loading credentials: {exc}", file=sys.stderr)
        return 1

    if not credentials:
        print(
            "No credentials provided. Use --credentials or --credential.",
            file=sys.stderr,
        )
        return 1

    if args.verbose:
        labels = ", ".join(c.label for c in credentials)
        print(f"Loaded {len(credentials)} credential(s): {labels}", file=sys.stderr)

    # -- Configure and run the pipeline --
    mode = (
        ReportMode.DETERMINISTIC
        if args.mode == "deterministic"
        else ReportMode.ENRICHED
    )

    cfg = PipelineConfig(
        report_mode=mode,
        transport_timeout_seconds=args.timeout,
    )

    if args.verbose:
        print("Running pipeline...", file=sys.stderr)

    transport = transport if transport is not None else _resolve_transport()

    pipeline = Pipeline(transport=transport, config=cfg)
    try:
        result = pipeline.run(
            exchanges=exchanges,
            credentials=credentials,
        )
    except Exception as exc:
        print(f"Pipeline error: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc(file=sys.stderr)
        return 1

    if args.verbose:
        print(f"Found {result.finding_count} finding(s).", file=sys.stderr)

    # -- Render and output --
    try:
        output = _render_output(result, args.format)
    except Exception as exc:
        print(f"Render error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        Path(args.output).write_text(output, "utf-8")
        if args.verbose:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


def _resolve_transport() -> TransportProtocol:
    """Resolve an HTTP transport for replay.

    Uses ``HttpxTransport`` when ``httpx`` is available, otherwise falls
    back to a stub that fails with a clear error message.
    """
    try:
        import httpx  # noqa: F401

        from charon.replay.httpx_transport import HttpxTransport

        return HttpxTransport()
    except ImportError:
        from charon.replay.errors import ReplayTransportError
        from charon.replay.transport import TransportRequest, TransportResponse

        class _MissingHttpxTransport:
            """Fallback transport that errors when used."""

            def send(self, request: TransportRequest) -> TransportResponse:
                raise ReplayTransportError(
                    "httpx is required for network replay; "
                    "install the 'replay' extra: pip install charon[replay]"
                )

        return _MissingHttpxTransport()


def _render_output(
    result: PipelineResult,
    fmt: str,
) -> str:
    """Render the pipeline result in the requested format(s).

    For ``both`` format, returns JSON followed by Markdown separated by
    a horizontal rule.
    """
    if fmt == "json":
        return render_json(result.report) + "\n"

    if fmt == "markdown":
        return render_markdown(result.report)

    # both
    json_out = render_json(result.report)
    md_out = render_markdown(result.report)
    separator = f"\n{'=' * 72}\n"
    return json_out + separator + md_out


if __name__ == "__main__":
    sys.exit(main())
