#!/usr/bin/env python3
"""Run Charon's deterministic pipeline against one pinned, local VAmPI target.

The script refuses non-loopback base URLs, recreates VAmPI's disposable test
DB, records only sanitized captures in a temporary directory, runs
`python -m charon analyze --mode deterministic`, and saves the raw Charon JSON
report plus an exact-count summary under docs/evaluation/raw by default.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH_PATH = Path(__file__).with_name("ground_truth.json")
EXPECTED_VAMPI_REVISION = "f16052dce83f05847133ec98f01c5193a41de7d8"
ALICE = "charon_eval_alice"
BOB = "charon_eval_bob"
DISPOSABLE = "charon_eval_disposable"
BOOK_TITLE = "charon_eval_alice_book"
ALICE_PASSWORD = "CharonEvalAlicePassword1"
BOB_PASSWORD = "CharonEvalBobPassword1"
DISPOSABLE_PASSWORD = "CharonEvalDisposablePassword1"
BOB_PASSWORD_AFTER_PROBE = "CharonEvalBobPasswordAfterProbe1"
ADMIN_PASSWORD = "pass1"  # Seeded by VAmPI's documented /createdb endpoint.


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
    body: bytes | None = None
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
        with urlopen(request, timeout=timeout) as response:
            return Observation(
                status_code=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=response.read(),
            )
    except HTTPError as error:
        return Observation(
            status_code=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=error.read(),
        )
    except (URLError, TimeoutError) as error:
        raise RuntimeError(
            f"Local VAmPI request failed for {method} {path}: {error}"
        ) from error


def _json_body(observation: Observation, context: str) -> dict[str, Any]:
    try:
        value = json.loads(observation.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Expected a JSON response from {context}; received HTTP "
            f"{observation.status_code}."
        ) from error
    if not isinstance(value, dict):
        raise RuntimeError(f"Expected an object response from {context}.")
    return value


def _require_status(
    observation: Observation,
    expected: int,
    context: str,
) -> None:
    if observation.status_code != expected:
        raise RuntimeError(
            f"{context}: expected HTTP {expected}, got "
            f"HTTP {observation.status_code}."
        )


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
            "such as http://127.0.0.1:5000."
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


def _vampi_revision(vampi_dir: Path) -> str:
    if not (vampi_dir / ".git").exists():
        raise SystemExit(
            f"VAmPI clone not found at {vampi_dir}. Clone the repository and "
            "pass --vampi-dir (see SETUP.md)."
        )
    revision = _git_value(vampi_dir, "rev-parse", "HEAD")
    if revision != EXPECTED_VAMPI_REVISION:
        raise SystemExit(
            "VAmPI revision mismatch: ground_truth.json is pinned to "
            f"{EXPECTED_VAMPI_REVISION}, but {vampi_dir} is at {revision}."
        )
    tracked_changes = _git_value(vampi_dir, "status", "--short", "--untracked-files=no")
    if tracked_changes:
        raise SystemExit(
            "The pinned VAmPI checkout has tracked modifications; refusing to "
            "evaluate a modified target."
        )
    return revision


def _charon_version() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "charon", "version"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _register_user(
    base_url: str,
    username: str,
    password: str,
    email: str,
    timeout: float,
) -> None:
    observation = _request(
        base_url,
        "POST",
        "/users/v1/register",
        payload={"username": username, "password": password, "email": email},
        timeout=timeout,
    )
    _require_status(observation, 200, f"Register {username}")
    response = _json_body(observation, f"register {username}")
    if response.get("status") != "success":
        raise RuntimeError(
            f"VAmPI did not register {username}; call /createdb on the isolated "
            "evaluation instance before retrying."
        )


def _login(
    base_url: str,
    username: str,
    password: str,
    timeout: float,
) -> str:
    observation = _request(
        base_url,
        "POST",
        "/users/v1/login",
        payload={"username": username, "password": password},
        timeout=timeout,
    )
    _require_status(observation, 200, f"Login {username}")
    response = _json_body(observation, f"login {username}")
    token = response.get("auth_token")
    if response.get("status") != "success" or not isinstance(token, str):
        raise RuntimeError(f"VAmPI login did not return a token for {username}.")
    return token


def _capture(
    base_url: str,
    *,
    case_id: str,
    method: str,
    path: str,
    token: str | None,
    payload: dict[str, Any] | None,
    expected_status: int,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    observation = _request(
        base_url,
        method,
        path,
        payload=payload,
        token=token,
        timeout=timeout,
    )
    _require_status(observation, expected_status, f"Baseline {case_id}")

    response_body: str | None
    if observation.body:
        response_body = observation.body.decode("utf-8")
    else:
        response_body = None

    # Store the auth header name with a placeholder, never the live token.
    request_headers = {"Accept": "application/json"}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if token is not None:
        request_headers["Authorization"] = "<redacted>"
    content_type = observation.headers.get("content-type")
    response_headers = {"Content-Type": content_type} if content_type else {}

    request_body = (
        json.dumps(payload, separators=(",", ":"))
        if payload is not None
        else None
    )
    record = {
        "case_id": case_id,
        "account_label": ALICE,
        "method": method,
        "url": f"{base_url}{path}",
        "status_code": observation.status_code,
        "request": {"headers": request_headers, "body": request_body},
        "response": {"headers": response_headers, "body": response_body},
    }
    log_entry = {
        "case_id": case_id,
        "method": method,
        "path": path,
        "baseline_status_code": observation.status_code,
    }
    return record, log_entry


def _exact_ratio(numerator: int, denominator: int) -> str | None:
    if denominator == 0:
        return None
    return str(Fraction(numerator, denominator))


def _summarize(
    ground_truth: dict[str, Any],
    report: dict[str, Any],
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    tested_cases = [
        case
        for case in ground_truth["cases"]
        if case["evaluation_status"] == "tested"
        and case["expected_result"] in {"vulnerable", "not_vulnerable"}
    ]
    case_by_key = {
        (case["method"], case["path"]): case for case in tested_cases
    }
    predictions: dict[str, set[str]] = {
        case["id"]: set() for case in tested_cases
    }
    observed_findings: list[dict[str, Any]] = []
    unmapped: list[str] = []

    for finding in report.get("findings", []):
        facts = {
            item["name"]: item["value"]
            for item in finding.get("observed_facts", [])
        }
        url = facts.get("url", "")
        method = facts.get("method", "")
        path = urlsplit(url).path
        case = case_by_key.get((method, path))
        if case is None and not method:
            candidates = [item for item in tested_cases if item["path"] == path]
            if len(candidates) == 1:
                case = candidates[0]
        if case is None:
            unmapped.append(str(finding.get("finding_id", "<missing-id>")))
            continue
        owasp_class = str(finding.get("owasp_class", ""))
        predictions[case["id"]].add(owasp_class)
        observed_findings.append(
            {
                "case_id": case["id"],
                "finding_id": finding.get("finding_id"),
                "rule_id": finding.get("rule_id"),
                "owasp_class": owasp_class,
                "method": method or case["method"],
                "path": path,
                "replay_identity": facts.get("replay_identity"),
            }
        )

    if unmapped:
        raise RuntimeError(
            "Charon emitted findings that could not be mapped to a labeled "
            f"case: {', '.join(unmapped)}. The raw report is saved; review it "
            "before interpreting metrics."
        )

    case_results: list[dict[str, Any]] = []
    for case in tested_cases:
        case_results.append(
            {
                "case_id": case["id"],
                "method": case["method"],
                "path": case["path"],
                "expected_result": case["expected_result"],
                "expected_owasp_classes": case["expected_owasp_classes"],
                "baseline_status_code": next(
                    item["baseline_status_code"]
                    for item in observations
                    if item["case_id"] == case["id"]
                ),
                "observed_owasp_classes": sorted(predictions[case["id"]]),
            }
        )

    metrics: list[dict[str, Any]] = []
    for evaluation_class in ground_truth["evaluation_classes"]:
        code = evaluation_class["owasp_class"]
        positive_cases = {
            case["id"]
            for case in tested_cases
            if case["expected_result"] == "vulnerable"
            and code in case["expected_owasp_classes"]
        }
        negative_cases = {
            case["id"]
            for case in tested_cases
            if code not in case["expected_owasp_classes"]
        }
        predicted_cases = {
            case_id for case_id, classes in predictions.items() if code in classes
        }
        true_positives = len(positive_cases & predicted_cases)
        false_negatives = len(positive_cases - predicted_cases)
        false_positives = len(negative_cases & predicted_cases)
        true_negatives = len(negative_cases - predicted_cases)
        metrics.append(
            {
                "owasp_class": code,
                "name": evaluation_class["name"],
                "rule_id": evaluation_class["rule_id"],
                "test_cases": len(positive_cases) + len(negative_cases),
                "positive_cases": len(positive_cases),
                "negative_cases": len(negative_cases),
                "true_positives": true_positives,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
                "true_negatives": true_negatives,
                "precision_exact": _exact_ratio(
                    true_positives, true_positives + false_positives
                ),
                "recall_exact": _exact_ratio(
                    true_positives, true_positives + false_negatives
                ),
            }
        )

    not_tested_cases = [
        {
            "case_id": case["id"],
            "expected_result": case["expected_result"],
            "vulnerability_class": case["vulnerability_class"],
            "status": "TBD",
            "reason": case.get("not_tested_reason", "Not executed."),
        }
        for case in ground_truth["cases"]
        if case["evaluation_status"] != "tested"
    ]

    return {
        "schema_version": 1,
        "mode": report.get("mode"),
        "finding_count": report.get("finding_count"),
        "tested_case_count": len(tested_cases),
        "case_results": case_results,
        "observed_findings": sorted(
            observed_findings,
            key=lambda item: (
                item["case_id"],
                item["owasp_class"],
                item["replay_identity"] or "",
                item["finding_id"] or "",
            ),
        ),
        "metrics": metrics,
        "not_tested_cases": not_tested_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5000",
        help="Loopback VAmPI URL only (default: http://127.0.0.1:5000).",
    )
    parser.add_argument(
        "--vampi-dir",
        type=Path,
        default=Path(os.environ.get("VAMPI_DIR", "/tmp/charon-eval-vampi")),
        help=(
            "External VAmPI Git clone used to verify the pinned revision "
            "(or VAMPI_DIR)."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "docs/evaluation/raw",
        help="Directory for raw Charon JSON and the exact-count run summary.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Timeout for VAmPI setup/capture HTTP requests (default: 8 seconds).",
    )
    args = parser.parse_args()

    base_url = _local_base_url(args.base_url)
    vampi_dir = args.vampi_dir.resolve()
    vampi_revision = _vampi_revision(vampi_dir)
    try:
        charon_version = _charon_version()
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        raise SystemExit(
            "Charon is not installed in this Python environment. From the Charon "
            "repository root, install `python -m pip install -e '.[replay]'`."
        ) from error

    # Guard against accidentally evaluating modified detection code. Docs and
    # this runner may be uncommitted, but tracked Charon implementation files
    # must be unchanged from HEAD.
    changed_charon_files = _git_value(REPO_ROOT, "status", "--short", "--", "charon")
    if changed_charon_files:
        raise SystemExit(
            "Refusing to run because tracked Charon files are modified. This "
            "evaluation does not change detection logic."
        )

    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    if ground_truth["target"]["revision"] != vampi_revision:
        raise SystemExit("Ground-truth VAmPI revision does not match the clone.")

    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "charon-report.json"
    summary_path = output_dir / "run-summary.json"
    stderr_path = output_dir / "charon-stderr.log"
    stdout_path = output_dir / "charon-stdout.log"

    root_observation = _request(
        base_url, "GET", "/", timeout=args.timeout
    )
    _require_status(root_observation, 200, "VAmPI health check")
    root_body = _json_body(root_observation, "VAmPI health check")
    if root_body.get("message") != "VAmPI the Vulnerable API":
        raise SystemExit(
            "The loopback target did not identify itself as VAmPI; refusing to "
            "send the evaluation probes."
        )
    if root_body.get("vulnerable") != 1:
        raise SystemExit(
            "The local VAmPI target did not report vulnerable=1; stop and "
            "start the pinned VAmPI with vulnerable=1."
        )

    # /createdb drops and recreates VAmPI's disposable database. Retry only
    # because upstream seeds dummy book titles with random integers, which can
    # collide; every retry starts by dropping the database again.
    reset_status: int | None = None
    reset_attempts = 0
    for attempt in range(1, 6):
        reset_attempts = attempt
        reset = _request(base_url, "GET", "/createdb", timeout=args.timeout)
        reset_status = reset.status_code
        if reset.status_code == 200:
            break
    if reset_status != 200:
        raise RuntimeError(
            f"VAmPI /createdb did not succeed (last HTTP status {reset_status})."
        )

    _register_user(
        base_url, ALICE, ALICE_PASSWORD, "charon-alice@example.test", args.timeout
    )
    _register_user(
        base_url, BOB, BOB_PASSWORD, "charon-bob@example.test", args.timeout
    )
    _register_user(
        base_url,
        DISPOSABLE,
        DISPOSABLE_PASSWORD,
        "charon-disposable@example.test",
        args.timeout,
    )

    alice_token = _login(base_url, ALICE, ALICE_PASSWORD, args.timeout)
    bob_token = _login(base_url, BOB, BOB_PASSWORD, args.timeout)
    admin_token = _login(base_url, "admin", ADMIN_PASSWORD, args.timeout)

    book_create = _request(
        base_url,
        "POST",
        "/books/v1",
        payload={"book_title": BOOK_TITLE, "secret": "synthetic-charon-eval-secret"},
        token=alice_token,
        timeout=args.timeout,
    )
    _require_status(book_create, 200, "Create Alice's synthetic book")
    created_book = _json_body(book_create, "create Alice's synthetic book")
    if created_book.get("status") != "success":
        raise RuntimeError("VAmPI did not create the synthetic Alice-owned book.")

    ground_cases = {
        case["id"]: case
        for case in ground_truth["cases"]
        if case["evaluation_status"] == "tested"
    }
    probes = [
        (
            "password-change-cross-user",
            "PUT",
            f"/users/v1/{BOB}/password",
            alice_token,
            {"password": BOB_PASSWORD_AFTER_PROBE},
        ),
        (
            "book-cross-account",
            "GET",
            f"/books/v1/{BOOK_TITLE}",
            alice_token,
            None,
        ),
        ("home-public", "GET", "/", None, None),
        ("users-list-public", "GET", "/users/v1", None, None),
        (
            "user-profile-public",
            "GET",
            f"/users/v1/{ALICE}",
            None,
            None,
        ),
        ("debug-sensitive-data", "GET", "/users/v1/_debug", None, None),
        ("me-current-user", "GET", "/me", alice_token, None),
        (
            "admin-only-delete",
            "DELETE",
            f"/users/v1/{DISPOSABLE}",
            alice_token,
            None,
        ),
    ]

    if {probe[0] for probe in probes} != set(ground_cases):
        raise SystemExit(
            "The tested probe list and ground_truth.json do not match; update "
            "them together before running."
        )

    records: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for case_id, method, path, token, payload in probes:
        case = ground_cases[case_id]
        if case["method"] != method or case["path"] != path:
            raise SystemExit(
                f"Probe {case_id} ({method} {path}) does not match its "
                "ground_truth.json label."
            )
        record, log_entry = _capture(
            base_url,
            case_id=case_id,
            method=method,
            path=path,
            token=token,
            payload=payload,
            expected_status=case["baseline_status_code"],
            timeout=args.timeout,
        )
        records.append(record)
        observations.append(log_entry)

    credentials = [
        {"label": BOB, "bearer_token": bob_token},
        {"label": "admin", "bearer_token": admin_token},
    ]

    with tempfile.TemporaryDirectory(prefix="charon-vampi-eval-") as temp_dir:
        temp_path = Path(temp_dir)
        capture_path = temp_path / "captures.json"
        credentials_path = temp_path / "credentials.json"
        capture_path.write_text(
            json.dumps(records, indent=2, sort_keys=True), encoding="utf-8"
        )
        credentials_path.write_text(
            json.dumps(credentials, indent=2), encoding="utf-8"
        )

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
                "Charon analyze failed; temporary captures and credentials were "
                "removed. See docs/evaluation/raw/charon-stderr.log."
            )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("mode") != "deterministic":
        raise RuntimeError(
            f"Expected deterministic Charon mode, got {report.get('mode')!r}."
        )

    summary = _summarize(ground_truth, report, observations)
    summary.update(
        {
            "charon_version": charon_version,
            "charon_commit_hash": _git_value(REPO_ROOT, "rev-parse", "HEAD"),
            "vampi_version": "OpenAPI info.version "
            + str(ground_truth["target"]["openapi_version"]),
            "vampi_commit_hash": vampi_revision,
            "target_base_url": base_url,
            "database_reset_attempts": reset_attempts,
            "python_version": platform.python_version(),
            "mode": "deterministic",
            "charon_command": [
                "python -m charon analyze <temporary-captures.json>",
                "--credentials <temporary-credentials.json>",
                "--format json",
                "--mode deterministic",
                "--output docs/evaluation/raw/charon-report.json",
                "--verbose",
            ],
            "baseline_observations": observations,
            "raw_report_file": report_path.name,
            "stderr_log_file": stderr_path.name,
            "stdout_log_file": stdout_path.name,
        }
    )
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["metrics"], indent=2, sort_keys=True))
    print(f"Raw Charon report: {report_path}")
    print(f"Run summary:       {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
