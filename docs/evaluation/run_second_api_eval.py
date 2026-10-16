#!/usr/bin/env python3
"""Run a small deterministic Charon check against the pinned ShopAPI lab.

The script accepts loopback targets only, blocks redirects outside the original
loopback origin, verifies the pinned source checkout, uses seeded synthetic
accounts, stores only a sanitized capture, and runs
Charon's normal CLI. It never starts the target or requires Docker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH_PATH = Path(__file__).with_name("second_api_ground_truth.json")
EXPECTED_REVISION = "4ebf2b57abdab076d1bbc092132819925573cde1"
ALICE_PASSWORD = "password123"
BOB_PASSWORD = "password456"


class _LoopbackRedirectHandler(HTTPRedirectHandler):
    """Allow only redirects that remain on the original loopback origin."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> Request | None:
        source = urlsplit(req.full_url)
        target = urlsplit(newurl)
        try:
            source_port = source.port if source.port is not None else 80
            target_port = target.port if target.port is not None else 80
        except ValueError:
            source_port = target_port = -1

        loopback_hosts = {"127.0.0.1", "localhost", "::1"}
        same_loopback_origin = (
            source.scheme == "http"
            and target.scheme == "http"
            and source.hostname in loopback_hosts
            and target.hostname in loopback_hosts
            and source.hostname == target.hostname
            and source_port == target_port
            and target.username is None
            and target.password is None
        )
        if not same_loopback_origin:
            raise HTTPError(
                req.full_url,
                code,
                "Refusing redirect outside the local evaluation origin.",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class Observation:
    status_code: int
    headers: dict[str, str]
    body: bytes


def _request(
    base_url: str,
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
    timeout: float,
) -> Observation:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        f"{base_url}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        opener = build_opener(_LoopbackRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            return Observation(
                response.status,
                {name.lower(): value for name, value in response.headers.items()},
                response.read(),
            )
    except HTTPError as error:
        return Observation(
            error.code,
            {name.lower(): value for name, value in error.headers.items()},
            error.read(),
        )
    except (URLError, TimeoutError) as error:
        raise RuntimeError(
            f"Local ShopAPI request failed for {method} {path}: {error}"
        ) from error


def _json_body(observation: Observation, context: str) -> dict[str, Any]:
    try:
        value = json.loads(observation.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Expected JSON from {context}; received HTTP {observation.status_code}."
        ) from error
    if not isinstance(value, dict):
        raise RuntimeError(f"Expected a JSON object from {context}.")
    return value


def _local_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SystemExit(
            "Refusing to test a non-loopback or non-HTTP target. Use a base URL "
            "such as http://127.0.0.1:5001."
        )
    return value.rstrip("/")


def _git_value(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _verify_target(target_dir: Path) -> str:
    if not (target_dir / ".git").exists():
        raise SystemExit(f"Pinned ShopAPI clone not found at {target_dir}.")
    revision = _git_value(target_dir, "rev-parse", "HEAD")
    if revision != EXPECTED_REVISION:
        raise SystemExit(
            f"ShopAPI revision mismatch: expected {EXPECTED_REVISION}, got {revision}."
        )
    changes = _git_value(
        target_dir, "status", "--short", "--untracked-files=no"
    )
    if changes:
        raise SystemExit(
            "Pinned ShopAPI checkout has tracked changes; refusing to run."
        )
    return revision


def _login(base_url: str, username: str, password: str, timeout: float) -> str:
    response = _request(
        base_url,
        "POST",
        "/api/auth/login",
        payload={"username": username, "password": password},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"ShopAPI login for {username} expected HTTP 200, "
            f"got {response.status_code}."
        )
    token = _json_body(response, f"login {username}").get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"ShopAPI login returned no token for {username}.")
    return token


def _order_owner_id(observation: Observation) -> int:
    value = _json_body(observation, "order request").get("user_id")
    if not isinstance(value, int):
        raise RuntimeError("ShopAPI order response has no integer user_id.")
    return value


def _charon_version() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "charon", "version"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _findings_for_case(
    report: dict[str, Any],
    method: str,
    path: str,
) -> list[dict[str, Any]]:
    matched = []
    for finding in report.get("findings", []):
        facts = {
            item["name"]: item["value"]
            for item in finding.get("observed_facts", [])
        }
        if (
            facts.get("method") == method
            and urlsplit(facts.get("url", "")).path == path
        ):
            matched.append(
                {
                    "finding_id": finding.get("finding_id"),
                    "rule_id": finding.get("rule_id"),
                    "owasp_class": finding.get("owasp_class"),
                    "severity": finding.get("severity"),
                }
            )
    return sorted(matched, key=lambda item: item["finding_id"] or "")


def _prepare_output_dir(output_dir: Path) -> Path:
    try:
        if output_dir.exists():
            if not output_dir.is_dir():
                raise SystemExit(f"Output path is not a directory: {output_dir}.")
            if next(output_dir.iterdir(), None) is not None:
                raise SystemExit(
                    f"Output directory is not empty: {output_dir}. Refusing to "
                    "overwrite evaluation results; choose a new empty directory "
                    "with --output-dir."
                )
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SystemExit(
            f"Cannot prepare output directory {output_dir}: {error}"
        ) from error
    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5001",
        help="Loopback ShopAPI URL only (default: http://127.0.0.1:5001).",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(
            os.environ.get(
                "OWASP_API_TOP10_LAB_DIR",
                "/tmp/charon-eval-owasp-api-top10-lab",
            )
        ),
        help="External pinned ShopAPI Git clone path.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "New empty output directory for capture, report, logs, and summary; "
            "if omitted, a fresh temporary directory is created. Nonempty "
            "directories are refused."
        ),
    )
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    base_url = _local_base_url(args.base_url)
    target_dir = args.target_dir.resolve()
    target_revision = _verify_target(target_dir)
    changed_charon_files = _git_value(
        REPO_ROOT, "status", "--short", "--", "charon"
    )
    if changed_charon_files:
        raise SystemExit(
            "Refusing to run because Charon implementation files are modified."
        )

    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    if ground_truth["target"]["revision"] != target_revision:
        raise SystemExit("Second-API ground-truth revision does not match the clone.")
    cases = ground_truth["cases"]
    if len(cases) != 1:
        raise SystemExit("This runner expects exactly one labelled API1 case.")
    case = cases[0]
    if case["expected_result"] != "vulnerable" or case["owasp_class"] != "API1":
        raise SystemExit(
            "The pinned ShopAPI case must remain labelled vulnerable API1."
        )

    output_dir = args.output_dir
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="charon-eval-shopapi-"))
    elif not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir = _prepare_output_dir(output_dir.resolve())

    charon_version = _charon_version()
    health = _request(base_url, "GET", "/", timeout=args.timeout)
    if health.status_code != 200:
        raise RuntimeError(
            f"ShopAPI health check expected HTTP 200, got {health.status_code}."
        )
    if (
        _json_body(health, "ShopAPI health check").get("api")
        != "ShopAPI Vulnerable Lab"
    ):
        raise RuntimeError("The loopback target did not identify itself as ShopAPI.")

    alice_token = _login(base_url, "alice", ALICE_PASSWORD, args.timeout)
    bob_token = _login(base_url, "bob", BOB_PASSWORD, args.timeout)
    unauthenticated = _request(
        base_url, case["method"], case["path"], timeout=args.timeout
    )
    alice_order = _request(
        base_url,
        case["method"],
        case["path"],
        token=alice_token,
        timeout=args.timeout,
    )
    bob_order = _request(
        base_url,
        case["method"],
        case["path"],
        token=bob_token,
        timeout=args.timeout,
    )
    if unauthenticated.status_code != 401:
        raise RuntimeError(
            f"Expected unauthenticated request to return 401, got "
            f"{unauthenticated.status_code}."
        )
    if alice_order.status_code != case["baseline_status_code"]:
        raise RuntimeError(
            f"Alice's labelled probe expected HTTP {case['baseline_status_code']}, "
            f"got {alice_order.status_code}."
        )
    if bob_order.status_code != 200:
        raise RuntimeError(
            f"Bob owner control expected HTTP 200, got {bob_order.status_code}."
        )
    expected_owner_id = case["object_owner_id"]
    if _order_owner_id(alice_order) != expected_owner_id:
        raise RuntimeError(
            "Alice's response did not contain the labelled Bob-owned order."
        )
    if _order_owner_id(bob_order) != expected_owner_id:
        raise RuntimeError("Bob's owner-control response did not contain order 2.")

    response_body = alice_order.body.decode("utf-8")
    content_type = alice_order.headers.get("content-type")
    record = {
        "case_id": case["id"],
        "account_label": case["caller"],
        "method": case["method"],
        "url": f"{base_url}{case['path']}",
        "status_code": alice_order.status_code,
        "request": {
            "headers": {
                "Accept": "application/json",
                "Authorization": "<redacted>",
            }
        },
        "response": {
            "headers": {"Content-Type": content_type} if content_type else {},
            "body": response_body,
        },
    }
    capture_path = output_dir / "capture.json"
    capture_path.write_text(json.dumps([record], indent=2, sort_keys=True) + "\n")
    report_path = output_dir / "charon-report.json"
    stderr_path = output_dir / "charon-stderr.log"
    stdout_path = output_dir / "charon-stdout.log"
    credentials = [{"label": "bob", "bearer_token": bob_token}]

    with tempfile.TemporaryDirectory(prefix="charon-second-api-eval-") as temp_dir:
        credentials_path = Path(temp_dir) / "credentials.json"
        credentials_path.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "charon",
            "analyze",
            str(capture_path),
            "--credentials",
            str(credentials_path),
            "--format",
            "json",
            "--mode",
            "deterministic",
            "--output",
            str(report_path),
            "--verbose",
        ]
        result = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        stderr_path.write_text(result.stderr, encoding="utf-8")
        stdout_path.write_text(result.stdout, encoding="utf-8")
        if result.returncode != 0:
            raise RuntimeError(
                "Charon analyze failed; see the saved stderr log. Temporary "
                "credentials were removed."
            )

    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    case_findings = _findings_for_case(report, case["method"], case["path"])
    api1_findings = [
        finding
        for finding in case_findings
        if finding["owasp_class"] == case["owasp_class"]
    ]
    detected = bool(api1_findings)
    findings_by_class: dict[str, int] = {}
    for finding in report.get("findings", []):
        owasp_class = str(finding.get("owasp_class", ""))
        findings_by_class[owasp_class] = findings_by_class.get(owasp_class, 0) + 1
    observations = {
        "health_status_code": health.status_code,
        "unauthenticated_status_code": unauthenticated.status_code,
        "alice_cross_account_status_code": alice_order.status_code,
        "alice_response_object_owner_id": expected_owner_id,
        "bob_owner_control_status_code": bob_order.status_code,
        "bob_owner_control_object_owner_id": expected_owner_id,
    }
    summary = {
        "schema_version": 1,
        "target_name": ground_truth["target"]["name"],
        "target_repository": ground_truth["target"]["repository"],
        "target_revision": target_revision,
        "target_base_url": base_url,
        "target_runtime": ground_truth["target"]["runtime"],
        "docker_used": False,
        "python_version": platform.python_version(),
        "charon_version": charon_version,
        "charon_commit_hash": _git_value(REPO_ROOT, "rev-parse", "HEAD"),
        "mode": "deterministic",
        "case_count": 1,
        "case_result": {
            "case_id": case["id"],
            "method": case["method"],
            "path": case["path"],
            "expected_result": case["expected_result"],
            "expected_owasp_class": case["owasp_class"],
            "caller": case["caller"],
            "object_owner": case["object_owner"],
            "charon_result": "detected" if detected else "not-detected",
            "matched_findings": case_findings,
            "matched_api1_findings": api1_findings,
            "additional_owasp_classes": sorted(
                {
                    finding["owasp_class"]
                    for finding in case_findings
                    if finding["owasp_class"] != case["owasp_class"]
                }
            ),
        },
        "finding_count": report.get("finding_count"),
        "findings_by_owasp_class": dict(sorted(findings_by_class.items())),
        "api1_finding_count_for_case": len(api1_findings),
        "metrics_note": (
            "Precision/recall are not calculated: this cross-check contains "
            "one labelled vulnerable case and no labelled negative controls."
        ),
        "observations": observations,
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "charon_command": [
            "python -m charon analyze capture.json",
            "--credentials <temporary-credentials.json>",
            "--format json",
            "--mode deterministic",
            "--output charon-report.json",
            "--verbose",
        ],
        "capture_file": capture_path.name,
        "raw_report_file": report_path.name,
        "stderr_log_file": stderr_path.name,
        "stdout_log_file": stdout_path.name,
    }
    (output_dir / "probe-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "run-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
