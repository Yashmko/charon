from __future__ import annotations

import json
from dataclasses import dataclass, field

from charon.detect.input import DetectionInput
from charon.detect.rules import (
    Rule,
    RuleConfig,
    RuleMatch,
    _has_meaningful_body_diff,
    _subject,
)
from charon.model import AccessDecision, OwaspClass, Provenanced, Severity

__all__ = ["BoplaRule"]


_VOLATILE_LEAF_NAMES: frozenset[str] = frozenset({
    "id", "uuid", "guid",
    "count", "total", "page", "offset", "limit",
    "timestamp", "created_at", "updated_at", "deleted_at",
})


def _is_volatile_key(key: str) -> bool:
    return key.lower() in _VOLATILE_LEAF_NAMES


def _count_data_fields(item: DetectionInput) -> int:
    body = item.baseline_exchange.response.body
    if body is None:
        return 0
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 0
    if not isinstance(parsed, dict):
        return 0
    return sum(1 for key in parsed if not _is_volatile_key(key))


@dataclass(frozen=True, slots=True)
class BoplaRule:
    config: RuleConfig = field(default_factory=RuleConfig)

    @property
    def rule_id(self) -> str:
        return "authz.bopla.excessive-data-exposure"

    def evaluate(self, item: DetectionInput) -> RuleMatch | None:
        if not self.config.enable_bopla:
            return None
        if not item.is_cross_identity:
            return None
        if item.comparison.baseline.access_decision is not AccessDecision.GRANTED:
            return None
        if item.comparison.other.access_decision is not AccessDecision.GRANTED:
            return None
        if _has_meaningful_body_diff(item, self.config.bola_body_diff_prefixes):
            return None

        field_count = _count_data_fields(item)
        if field_count < self.config.bopla_min_data_fields:
            return None

        subject = _subject(item)
        subject["body_field_count"] = Provenanced.derived(str(field_count))
        return RuleMatch(
            rule_id=self.rule_id,
            owasp_class=OwaspClass.API3_BOPLA,
            severity=self.config.bopla_severity,
            subject=subject,
        )
