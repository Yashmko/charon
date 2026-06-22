"""The comparison engine: deterministic baseline-vs-replay diffing.

:class:`ComparisonEngine` consumes a baseline
:class:`~charon.model.CapturedExchange` and a successful
:class:`~charon.model.ReplayResult` and emits a structured, content-addressed
:class:`~charon.model.Comparison`.

Everything here is a pure, deterministic transformation: no wall-clock, no
randomness, no network, no LLM. The engine never mutates its inputs and never
infers vulnerabilities, ownership, or authorization policy -- it only
describes *what differs*.
"""

from __future__ import annotations

import hashlib
import json

from charon.compare.config import ComparisonConfig
from charon.model import (
    AccessDecision,
    CapturedExchange,
    Comparison,
    FieldDiff,
    HttpMessage,
    ReplayResult,
    ResponseSnapshot,
)

__all__ = ["ComparisonEngine", "classify_access_decision"]

#: Status codes that mechanically denote access was denied. This is a
#: classification of the HTTP outcome, not an authorization judgement.
_DENIED_STATUSES = frozenset({401, 403, 404})


def classify_access_decision(status_code: int) -> AccessDecision:
    """Classify an HTTP status code into an :class:`AccessDecision`.

    Purely mechanical and deterministic:

    * ``2xx`` -> :attr:`AccessDecision.GRANTED`
    * ``401`` / ``403`` / ``404`` -> :attr:`AccessDecision.DENIED`
    * anything else (``1xx`` / ``3xx`` / ``5xx`` / other ``4xx``) ->
      :attr:`AccessDecision.INDETERMINATE`

    This is a status-code classification only. It is *not* a finding and does
    not assert that any access *should* have been granted or denied.
    """
    if 200 <= status_code < 300:
        return AccessDecision.GRANTED
    if status_code in _DENIED_STATUSES:
        return AccessDecision.DENIED
    return AccessDecision.INDETERMINATE


def _digest(body: bytes | None) -> str:
    """Return a stable ``sha256:`` digest of a body (``''`` hash for None)."""
    return "sha256:" + hashlib.sha256(body if body is not None else b"").hexdigest()


def _header_map(
    headers: tuple[tuple[str, str], ...],
) -> dict[str, tuple[str, ...]]:
    """Group header values by lower-cased name, preserving multiplicity.

    Values for each name are sorted so the comparison is order-insensitive
    and deterministic (e.g. multiple ``Vary`` headers).
    """
    grouped: dict[str, list[str]] = {}
    for name, value in headers:
        grouped.setdefault(name.lower(), []).append(value)
    return {name: tuple(sorted(values)) for name, values in grouped.items()}


def _flatten_json(payload: object, prefix: str) -> dict[str, str]:
    """Flatten a JSON structure into deterministic ``path -> value`` strings.

    Object keys are visited in sorted order and list items by index, so the
    flattening is stable. Scalar values are rendered with :func:`json.dumps`
    (sorted keys) to give a canonical string form.
    """
    flat: dict[str, str] = {}
    if isinstance(payload, dict):
        for key in sorted(payload):
            flat.update(_flatten_json(payload[key], f"{prefix}.{key}"))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            flat.update(_flatten_json(item, f"{prefix}[{index}]"))
    else:
        flat[prefix] = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return flat


class ComparisonEngine:
    """Builds deterministic ``Comparison`` artifacts from response pairs.

    :param config: Deterministic comparison configuration (volatile-field
        rules). Defaults to a config with sensible volatile-field defaults.
    """

    def __init__(self, config: ComparisonConfig | None = None) -> None:
        self._config = config if config is not None else ComparisonConfig()

    @property
    def config(self) -> ComparisonConfig:
        """The engine's deterministic configuration."""
        return self._config

    def compare(
        self,
        baseline: CapturedExchange,
        replay: ReplayResult,
    ) -> Comparison:
        """Compare a baseline exchange's response with a replay result.

        Produces a :class:`~charon.model.Comparison` referencing the
        baseline exchange id and the replay result id. The engine compares
        only the *response* side (status, headers, body), since that is what
        a replay observes against its baseline.
        """
        diffs: list[FieldDiff] = []
        diffs.extend(self._status_diff(baseline.status_code, replay.status_code))
        diffs.extend(
            self._header_diffs(baseline.response.headers, replay.response.headers)
        )
        diffs.extend(self._body_diffs(baseline.response, replay.response))
        diffs.extend(self._redirect_diffs(replay.nondeterminism_notes))

        return Comparison(
            baseline_ref=baseline.exchange_id,
            other_ref=replay.result_id,
            baseline=ResponseSnapshot(
                status_code=baseline.status_code,
                access_decision=classify_access_decision(baseline.status_code),
            ),
            other=ResponseSnapshot(
                status_code=replay.status_code,
                access_decision=classify_access_decision(replay.status_code),
            ),
            field_diffs=tuple(diffs),
        )

    @staticmethod
    def _status_diff(baseline: int, other: int) -> list[FieldDiff]:
        if baseline == other:
            return []
        return [FieldDiff("status_code", str(baseline), str(other))]

    def _header_diffs(
        self,
        baseline_headers: tuple[tuple[str, str], ...],
        other_headers: tuple[tuple[str, str], ...],
    ) -> list[FieldDiff]:
        baseline_map = _header_map(baseline_headers)
        other_map = _header_map(other_headers)
        diffs: list[FieldDiff] = []
        for name in sorted(set(baseline_map) | set(other_map)):
            if self._config.is_volatile_header(name):
                continue
            base_values = baseline_map.get(name)
            other_values = other_map.get(name)
            if base_values == other_values:
                continue
            diffs.append(
                FieldDiff(
                    location=f"header.{name}",
                    baseline_value=_join(base_values),
                    other_value=_join(other_values),
                )
            )
        return diffs

    def _body_diffs(
        self,
        baseline: HttpMessage,
        other: HttpMessage,
    ) -> list[FieldDiff]:
        diffs: list[FieldDiff] = []

        base_len = len(baseline.body) if baseline.body is not None else 0
        other_len = len(other.body) if other.body is not None else 0
        if base_len != other_len:
            diffs.append(
                FieldDiff("body.length", str(base_len), str(other_len))
            )

        base_json = self._maybe_json(baseline.body)
        other_json = self._maybe_json(other.body)
        if base_json is not None or other_json is not None:
            diffs.extend(self._json_body_diffs(base_json, other_json))
            return diffs

        # Non-JSON / binary: compare by digest only, never raw bytes.
        base_digest = _digest(baseline.body)
        other_digest = _digest(other.body)
        if base_digest != other_digest:
            diffs.append(
                FieldDiff("body.sha256", base_digest, other_digest)
            )
        return diffs

    def _json_body_diffs(
        self,
        baseline: object | None,
        other: object | None,
    ) -> list[FieldDiff]:
        base_flat = _flatten_json(baseline, "body") if baseline is not None else {}
        other_flat = _flatten_json(other, "body") if other is not None else {}
        diffs: list[FieldDiff] = []
        for path in sorted(set(base_flat) | set(other_flat)):
            leaf = _leaf_key(path)
            if self._config.is_volatile_body_key(leaf):
                continue
            base_value = base_flat.get(path)
            other_value = other_flat.get(path)
            if base_value == other_value:
                continue
            diffs.append(
                FieldDiff(
                    location=path,
                    baseline_value=base_value,
                    other_value=other_value,
                )
            )
        return diffs

    def _maybe_json(self, body: bytes | None) -> object | None:
        """Parse ``body`` as JSON, or return ``None`` if not JSON-decodable.

        Bodies above the configured size limit are treated as non-JSON so
        comparison stays bounded and digest-based.
        """
        if body is None:
            return None
        if len(body) > self._config.max_body_bytes_for_structured_diff:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def _redirect_diffs(notes: tuple[str, ...]) -> list[FieldDiff]:
        """Surface redirect chains recorded on the replay result.

        The baseline ``CapturedExchange`` has no redirect notes, so a replay
        that followed redirects is reported as a structured ``redirect``
        diff. This describes observed behavior only.
        """
        chains = [note for note in notes if note.startswith("redirect-chain:")]
        if not chains:
            return []
        return [
            FieldDiff(
                location="redirect",
                baseline_value=None,
                other_value="; ".join(sorted(chains)),
            )
        ]


def _join(values: tuple[str, ...] | None) -> str | None:
    """Render grouped header values as a single deterministic string."""
    if values is None:
        return None
    return ", ".join(values)


def _leaf_key(path: str) -> str:
    """Return the leaf key name of a flattened body path.

    Strips a trailing list index so e.g. ``body.items[2]`` -> ``items`` and
    ``body.user.id`` -> ``id``.
    """
    last = path.rsplit(".", 1)[-1]
    bracket = last.find("[")
    if bracket != -1:
        last = last[:bracket]
    return last
