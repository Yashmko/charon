"""Deterministic detection rules.

Each rule inspects a :class:`~charon.detect.input.DetectionInput` and returns
at most one :class:`RuleMatch`. Rules are pure and deterministic: identical
input yields an identical match (or no match). No rule performs semantic
interpretation or consults an LLM.

The two built-in rules are intentionally conservative -- each requires a
cross-identity replay *and* a clear, observable access signal before it will
match, to keep false positives low (see the module philosophy).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from charon.detect.input import DetectionInput
from charon.model import AccessDecision, OwaspClass, Provenanced, Severity

__all__ = [
    "RuleMatch",
    "RuleConfig",
    "Rule",
    "BolaRule",
    "BflaRule",
    "default_rules",
]


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A single rule's deterministic verdict that a finding is warranted.

    :param rule_id: Stable identifier of the rule that matched.
    :param owasp_class: OWASP API class for the finding.
    :param severity: Severity assigned by the rule (fixed per rule; never
        inflated by the engine).
    :param subject: Deterministic, provenance-tagged identifiers describing
        what the finding concerns. All values are non-LLM (Observed /
        Replayed / Derived).
    """

    rule_id: str
    owasp_class: OwaspClass
    severity: Severity
    subject: dict[str, Provenanced[str]]


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Declarative, deterministic configuration for the built-in rules.

    Severities and enablement are configurable so detection is rule-driven
    rather than relying on hard-coded magic at the call site.
    """

    enable_bola: bool = True
    enable_bfla: bool = True
    bola_severity: Severity = Severity.HIGH
    bfla_severity: Severity = Severity.HIGH
    #: Field-diff locations that, if present, indicate the cross-account
    #: response was *redacted/changed* and therefore is NOT a clean object
    #: exposure. Their presence suppresses the BOLA rule.
    bola_body_diff_prefixes: tuple[str, ...] = ("body",)


@runtime_checkable
class Rule(Protocol):
    """Protocol every detection rule implements."""

    @property
    def rule_id(self) -> str:
        """Stable identifier for this rule."""
        ...

    def evaluate(self, item: DetectionInput) -> RuleMatch | None:
        """Return a :class:`RuleMatch` if the rule fires, else ``None``."""
        ...


def _subject(item: DetectionInput) -> dict[str, Provenanced[str]]:
    """Build the deterministic subject common to authorization findings."""
    return {
        "method": Provenanced.observed(item.baseline_exchange.method),
        "url": Provenanced.observed(item.baseline_exchange.url),
        "baseline_account": Provenanced.observed(
            item.baseline_exchange.account_label
        ),
        "replay_identity": Provenanced.replayed(
            item.replay_request.identity.label
        ),
        "baseline_decision": Provenanced.derived(
            item.comparison.baseline.access_decision.value
        ),
        "replay_decision": Provenanced.derived(
            item.comparison.other.access_decision.value
        ),
    }


def _has_meaningful_body_diff(
    item: DetectionInput, prefixes: tuple[str, ...]
) -> bool:
    """Return ``True`` if any body-level field diff is present.

    Volatile fields were already stripped by ``compare``, so any remaining
    body diff means the cross-account response genuinely differed (e.g. was
    redacted). That makes an object-exposure claim indefensible, so the
    BOLA rule must not fire.
    """
    for diff in item.comparison.field_diffs:
        if any(
            diff.location == p or diff.location.startswith(f"{p}.")
            or diff.location.startswith(f"{p}[")
            for p in prefixes
        ):
            return True
    return False


@dataclass(frozen=True, slots=True)
class BolaRule:
    """Broken Object Level Authorization (OWASP API1) detector.

    Fires only when **all** hold:

    * the replay ran under a *different* identity than the baseline account;
    * both the baseline and replay access decisions are ``GRANTED``;
    * the cross-account response body is materially equivalent to the
      baseline (no remaining body field-diffs after volatile stripping).

    The body-equivalence requirement is the key false-positive guard: if the
    other account received a redacted/different body, access was effectively
    constrained and no defensible exposure finding exists.
    """

    config: RuleConfig = field(default_factory=RuleConfig)

    @property
    def rule_id(self) -> str:
        return "authz.bola.cross-account-object-exposure"

    def evaluate(self, item: DetectionInput) -> RuleMatch | None:
        if not self.config.enable_bola:
            return None
        if not item.is_cross_identity:
            return None
        if item.comparison.baseline.access_decision is not AccessDecision.GRANTED:
            return None
        if item.comparison.other.access_decision is not AccessDecision.GRANTED:
            return None
        if _has_meaningful_body_diff(item, self.config.bola_body_diff_prefixes):
            return None
        return RuleMatch(
            rule_id=self.rule_id,
            owasp_class=OwaspClass.API1_BOLA,
            severity=self.config.bola_severity,
            subject=_subject(item),
        )


@dataclass(frozen=True, slots=True)
class BflaRule:
    """Broken Function Level Authorization (OWASP API5) detector.

    Fires only when **all** hold:

    * the replay ran under a *different* identity than the baseline account;
    * the baseline access decision is ``DENIED``;
    * the replay access decision is ``GRANTED``.

    A ``DENIED -> GRANTED`` transition under a different identity is a clear,
    observable privilege exposure: a function denied to one context succeeded
    for another.
    """

    config: RuleConfig = field(default_factory=RuleConfig)

    @property
    def rule_id(self) -> str:
        return "authz.bfla.privilege-transition"

    def evaluate(self, item: DetectionInput) -> RuleMatch | None:
        if not self.config.enable_bfla:
            return None
        if not item.is_cross_identity:
            return None
        if item.comparison.baseline.access_decision is not AccessDecision.DENIED:
            return None
        if item.comparison.other.access_decision is not AccessDecision.GRANTED:
            return None
        return RuleMatch(
            rule_id=self.rule_id,
            owasp_class=OwaspClass.API5_BFLA,
            severity=self.config.bfla_severity,
            subject=_subject(item),
        )


def default_rules(config: RuleConfig | None = None) -> tuple[Rule, ...]:
    """Return the built-in rule set, configured by ``config``."""
    cfg = config if config is not None else RuleConfig()
    return (BolaRule(cfg), BflaRule(cfg))
