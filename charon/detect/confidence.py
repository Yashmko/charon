from __future__ import annotations

from collections import defaultdict

from charon.detect.input import DetectionInput
from charon.detect.rules import RuleConfig
from charon.model import Finding

__all__ = ["ConfidenceScorer", "score_findings"]

_MATRIX_RULE_PREFIXES: frozenset[str] = frozenset({
    "matrix.widespread-bola",
    "matrix.mutual-access",
})


def _is_matrix_rule(rule_id: str) -> bool:
    for prefix in _MATRIX_RULE_PREFIXES:
        if rule_id.startswith(prefix):
            return True
    return False


def score_findings(
    findings: tuple[Finding, ...],
    inputs: tuple[DetectionInput, ...],
    config: RuleConfig | None = None,
) -> dict[str, float]:
    return ConfidenceScorer(config).score(findings, inputs)


class ConfidenceScorer:
    def __init__(self, config: RuleConfig | None = None) -> None:
        self._config = config if config is not None else RuleConfig()

    def score(
        self,
        findings: tuple[Finding, ...],
        inputs: tuple[DetectionInput, ...],
    ) -> dict[str, float]:
        # Build a map: evidence.comparison_ref -> how many rules matched
        # for that input.
        comparison_rule_count: dict[str, int] = defaultdict(int)
        for finding in findings:
            if _is_matrix_rule(finding.rule_id):
                continue
            for evidence in finding.evidence:
                comparison_rule_count[evidence.comparison_ref] += 1

        # Count how many distinct baselines each replay identity accessed
        # (for matrix correlation bonus).
        replay_account_count: dict[str, int] = defaultdict(int)
        for inp in inputs:
            if not inp.is_cross_identity:
                continue
            if inp.comparison.other.access_decision.value != "granted":
                continue
            key = inp.replay_request.identity.label
            replay_account_count[key] += 1

        result: dict[str, float] = {}
        for finding in findings:
            result[finding.finding_id] = self._score_one(
                finding, comparison_rule_count, replay_account_count
            )
        return result

    def _score_one(
        self,
        finding: Finding,
        comparison_rule_count: dict[str, int],
        replay_account_count: dict[str, int],
    ) -> float:
        rule_id = finding.rule_id

        # Matrix findings get a high baseline.
        if _is_matrix_rule(rule_id):
            if rule_id.startswith("matrix.mutual-access"):
                return self._config.confidence_mutual_access_baseline
            return self._config.confidence_widespread_bola_baseline

        # Per-input rules: find max rule count across associated comparisons.
        max_rules = 0
        replay_identity: str | None = None
        for evidence in finding.evidence:
            count = comparison_rule_count.get(evidence.comparison_ref, 0)
            if count > max_rules:
                max_rules = count

        # Extract replay identity from subject if present.
        tagged = finding.subject.get("replay_identity")
        if tagged is not None:
            replay_identity = tagged.value

        base = self._base_confidence(rule_id)
        bonus = 0.0

        # Multiple rules on the same input increase confidence.
        if max_rules >= 2:
            bonus += self._config.confidence_multirule_bonus

        # If this replay identity accessed many accounts, surface the pattern.
        if replay_identity is not None:
            acc_count = replay_account_count.get(replay_identity, 0)
            if acc_count >= self._config.widespread_bola_threshold:
                bonus += self._config.confidence_widespread_bonus

        return min(base + bonus, 1.0)

    @staticmethod
    def _base_confidence(rule_id: str) -> float:
        if "missing-authz" in rule_id:
            return 0.9
        if "bfla" in rule_id:
            return 0.6
        if "bola" in rule_id:
            return 0.5
        if "bopla" in rule_id:
            return 0.4
        return 0.3
