"""Ownership inference engine.

The :class:`OwnershipEngine` analyzes captured exchanges and builds a
deterministic :class:`~charon.ownership.model.OwnershipMap` by scanning
response bodies for owner-related fields.

All inference is deterministic: no wall-clock, no randomness, no network,
no LLM. The same exchanges and config always produce byte-identical
ownership maps.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import cast

from charon.model import CapturedExchange
from charon.ownership.config import OwnershipConfig
from charon.ownership.model import OwnershipInference, OwnershipMap

__all__ = ["OwnershipEngine"]


class OwnershipEngine:
    """Builds deterministic ownership maps from captured exchanges.

    The engine performs two inference passes:

    1. **Owner-field pattern match (high confidence).** When a response JSON
       field matching a configured owner pattern (e.g. ``owner_id``) has a
       value equal to the exchange's account label, an inference is produced
       at ``owner_confidence`` (default: 0.85).

    2. **Account-label value match (moderate confidence).** When the account
       label appears anywhere else as a JSON scalar value in the response
       body, an inference is produced at ``account_label_confidence``
       (default: 0.60). Owner-field matches take priority; once a
       (URL, account) pair has been inferred at higher confidence, the same
       pair is not overwritten by a lower-confidence match.

    All inferences below ``min_confidence`` are filtered from the final
    output.

    :param config: Deterministic ownership configuration. Defaults to
        sensible defaults for common owner-field patterns.
    """

    def __init__(self, config: OwnershipConfig | None = None) -> None:
        self._config = config if config is not None else OwnershipConfig()

    @property
    def config(self) -> OwnershipConfig:
        """The engine's deterministic configuration."""
        return self._config

    def analyze(
        self, exchanges: Iterable[CapturedExchange]
    ) -> OwnershipMap:
        """Build an ownership map from captured exchanges.

        For each exchange, scans the response body JSON for fields matching
        configured owner patterns. When a field value matches the exchange's
        account label, ownership is inferred.

        :param exchanges: Captured exchanges to analyze.
        :returns: An :class:`OwnershipMap` with all qualifying inferences.
        """
        inferences: list[OwnershipInference] = []

        for exchange in exchanges:
            inferences.extend(self._analyze_one(exchange))

        return OwnershipMap(inferences=tuple(inferences))

    def _analyze_one(
        self, exchange: CapturedExchange
    ) -> list[OwnershipInference]:
        """Analyze a single exchange for ownership signals.

        Two-pass inference:
        1. Owner-field pattern matches (high confidence).
        2. Account-label value matches anywhere (moderate confidence), only
           for (URL, account) pairs not already inferred in pass 1.

        Results are filtered by ``min_confidence``.
        """
        result: list[OwnershipInference] = []

        body = exchange.response.body
        if body is None:
            return result

        parsed = self._maybe_json(body)
        if parsed is None:
            return result

        flat = _flatten_json(parsed, "body")
        account_label = exchange.account_label

        # Track (url, account) pairs already inferred so lower-confidence
        # pass-2 matches do not override higher-confidence pass-1 matches.
        already_inferred: set[tuple[str, str]] = set()

        # Pass 1: owner-field pattern matches (high confidence).
        for path, value in flat.items():
            if value != account_label:
                continue
            leaf_key = _leaf_key(path)
            if not self._config.is_owner_field(leaf_key):
                continue
            key = (exchange.url, account_label)
            if key not in already_inferred:
                already_inferred.add(key)
                result.append(
                    OwnershipInference(
                        url=exchange.url,
                        owning_account=account_label,
                        source_field=path,
                        source_exchange_id=exchange.exchange_id,
                        confidence=self._config.owner_confidence,
                    )
                )

        # Pass 2: account-label value matches anywhere (moderate confidence).
        for path, value in flat.items():
            if value != account_label:
                continue
            key = (exchange.url, account_label)
            if key in already_inferred:
                continue
            already_inferred.add(key)
            result.append(
                OwnershipInference(
                    url=exchange.url,
                    owning_account=account_label,
                    source_field=path,
                    source_exchange_id=exchange.exchange_id,
                    confidence=self._config.account_label_confidence,
                )
            )

        # Filter by minimum confidence threshold.
        if self._config.min_confidence > 0.0:
            result = [
                i for i in result
                if i.confidence >= self._config.min_confidence
            ]

        return result

    @staticmethod
    def _maybe_json(body: bytes | None) -> object | None:
        if body is None:
            return None
        try:
            return cast(object, json.loads(body.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            return None


def _flatten_json(payload: object, prefix: str) -> dict[str, str]:
    """Flatten a JSON structure into ``path -> string-value`` pairs.

    Object keys are visited in sorted order, list items by index, so the
    flattening is deterministic. String values are stored as-is without
    JSON quoting so they can be compared against account label strings.
    Numeric and other scalar values are rendered with ``json.dumps``.
    """
    flat: dict[str, str] = {}
    if isinstance(payload, dict):
        for key in sorted(payload):
            flat.update(_flatten_json(payload[key], f"{prefix}.{key}"))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            flat.update(_flatten_json(item, f"{prefix}[{index}]"))
    elif isinstance(payload, str):
        flat[prefix] = payload
    elif isinstance(payload, bool):
        flat[prefix] = "true" if payload else "false"
    elif payload is None:
        flat[prefix] = "null"
    else:
        flat[prefix] = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return flat


def _leaf_key(path: str) -> str:
    """Return the leaf key name of a flattened body path.

    Strips a trailing list index so e.g. ``body.user.id`` -> ``id`` and
    ``body.items[2]`` -> ``items``.
    """
    last = path.rsplit(".", 1)[-1]
    bracket = last.find("[")
    if bracket != -1:
        last = last[:bracket]
    return last

