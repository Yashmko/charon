from __future__ import annotations

from dataclasses import dataclass, field

from charon.detect.input import DetectionInput
from charon.detect.rules import RuleConfig, RuleMatch, _subject
from charon.model import AccessDecision, OwaspClass

__all__ = ["MissingAuthzRule"]


_AUTH_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
})


def _has_auth_header(item: DetectionInput) -> bool:
    for name, _ in item.baseline_exchange.request.headers:
        if name.lower() in _AUTH_HEADERS:
            return True
    return False


@dataclass(frozen=True, slots=True)
class MissingAuthzRule:
    config: RuleConfig = field(default_factory=RuleConfig)

    @property
    def rule_id(self) -> str:
        return "authz.missing-authz.no-authorization-header"

    def evaluate(self, item: DetectionInput) -> RuleMatch | None:
        if not self.config.enable_missing_authz:
            return None
        if not item.is_cross_identity:
            return None
        if item.comparison.other.access_decision is not AccessDecision.GRANTED:
            return None
        if _has_auth_header(item):
            return None
        return RuleMatch(
            rule_id=self.rule_id,
            owasp_class=OwaspClass.API7_MISSING_AUTHZ,
            severity=self.config.missing_authz_severity,
            subject=_subject(item),
        )
