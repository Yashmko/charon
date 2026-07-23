from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from charon.detect.input import DetectionInput
from charon.detect.rules import RuleConfig
from charon.model import (
    AccessDecision,
    Evidence,
    Finding,
    OwaspClass,
    Provenanced,
    Severity,
)

__all__ = ["MatrixAnalysis", "MatrixResult"]


@dataclass(frozen=True, slots=True)
class MatrixResult:
    findings: tuple[Finding, ...] = ()
    """Additional findings produced by cross-input analysis."""


@dataclass(frozen=True, slots=True)
class MatrixAnalysis:
    config: RuleConfig = field(default_factory=RuleConfig)

    def analyze(self, items: tuple[DetectionInput, ...]) -> MatrixResult:
        if not self.config.enable_matrix:
            return MatrixResult()

        findings: list[Finding] = []

        widespread = self._widespread_privilege(items)
        findings.extend(widespread)

        inversion = self._mutual_access(items)
        findings.extend(inversion)

        return MatrixResult(findings=tuple(findings))

    def _widespread_privilege(
        self, items: tuple[DetectionInput, ...]
    ) -> list[Finding]:
        threshold = self.config.widespread_bola_threshold
        groups: dict[tuple[str, str], list[DetectionInput]] = defaultdict(list)
        for item in items:
            if not item.is_cross_identity:
                continue
            if item.comparison.baseline.access_decision is not AccessDecision.GRANTED:
                continue
            if item.comparison.other.access_decision is not AccessDecision.GRANTED:
                continue
            key = (item.replay_request.identity.label, item.baseline_exchange.url)
            groups[key].append(item)

        results: list[Finding] = []
        for (identity, url), matched in groups.items():
            baseline_accounts: set[str] = set()
            for item in matched:
                baseline_accounts.add(item.baseline_exchange.account_label)
            if len(baseline_accounts) < threshold:
                continue

            subject: dict[str, Provenanced[str]] = {
                "replay_identity": Provenanced.replayed(identity),
                "url": Provenanced.observed(url),
                "accounts_accessed": Provenanced.derived(
                    str(len(baseline_accounts))
                ),
                "threshold": Provenanced.derived(str(threshold)),
            }
            evidence_list = [
                self._build_evidence(item) for item in matched
            ]
            results.append(
                Finding.create(
                    rule_id="matrix.widespread-bola.privilege-escalation-web",
                    owasp_class=OwaspClass.API1_BOLA,
                    severity=self.config.widespread_bola_severity,
                    subject=subject,
                    evidence=tuple(evidence_list),
                )
            )
        return results

    def _mutual_access(
        self, items: tuple[DetectionInput, ...]
    ) -> list[Finding]:
        pairs: dict[tuple[str, str], list[DetectionInput]] = defaultdict(list)
        for item in items:
            if not item.is_cross_identity:
                continue
            if item.comparison.baseline.access_decision is not AccessDecision.GRANTED:
                continue
            if item.comparison.other.access_decision is not AccessDecision.GRANTED:
                continue
            key = (item.baseline_exchange.account_label, item.replay_request.identity.label)
            pairs[key].append(item)

        results: list[Finding] = []
        seen_pairs: set[tuple[str, str]] = set()
        for (acc_a, acc_b), ab_items in pairs.items():
            if (acc_b, acc_a) in seen_pairs:
                continue
            ba_items = pairs.get((acc_b, acc_a))
            if ba_items is None:
                continue
            seen_pairs.add((acc_a, acc_b))
            seen_pairs.add((acc_b, acc_a))

            subject: dict[str, Provenanced[str]] = {
                "identity_a": Provenanced.observed(acc_a),
                "identity_b": Provenanced.observed(acc_b),
                "url": Provenanced.observed(ab_items[0].baseline_exchange.url),
            }
            all_items = ab_items + ba_items
            evidence_list = [
                self._build_evidence(item) for item in all_items
            ]
            results.append(
                Finding.create(
                    rule_id="matrix.mutual-access.privilege-inversion",
                    owasp_class=OwaspClass.API7_MISSING_AUTHZ,
                    severity=self.config.mutual_access_severity,
                    subject=subject,
                    evidence=tuple(evidence_list),
                )
            )
        return results

    @staticmethod
    def _build_evidence(item: DetectionInput) -> Evidence:
        return Evidence(
            comparison_ref=item.comparison.comparison_id,
            captured_exchange_refs=(item.baseline_exchange.exchange_id,),
            replay_pairs=(
                (item.replay_request.request_id, item.replay_result.result_id),
            ),
        )
