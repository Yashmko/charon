"""The detection engine: turn matches into evidence-backed findings.

:class:`DetectionEngine` applies a deterministic set of rules to
:class:`~charon.detect.input.DetectionInput` items, and for each match builds
the minimal backing :class:`~charon.model.Evidence` and emits a
:class:`~charon.model.Finding`.

Determinism guarantees:

* Rules are applied in a fixed order (sorted by ``rule_id``).
* Inputs are processed in the order given; the resulting findings are
  de-duplicated by ``finding_id`` and returned in a stable, sorted order.
* Every finding's id is a pure function of its content, so identical inputs
  reproduce identical finding identities across runs.

The engine is the sole creator of findings. It never consults an LLM and
performs no semantic interpretation.
"""

from __future__ import annotations

from collections.abc import Iterable

from charon.detect.input import DetectionInput
from charon.detect.rules import Rule, default_rules
from charon.model import Evidence, Finding

__all__ = ["DetectionEngine"]


class DetectionEngine:
    """Applies deterministic rules and emits evidence-backed findings.

    :param rules: The rule set to apply. Defaults to the built-in rules.
    """

    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        provided = tuple(rules) if rules is not None else default_rules()
        # Fixed evaluation order for determinism, regardless of input order.
        self._rules: tuple[Rule, ...] = tuple(
            sorted(provided, key=lambda r: r.rule_id)
        )

    @property
    def rules(self) -> tuple[Rule, ...]:
        """The engine's rules, in deterministic evaluation order."""
        return self._rules

    @staticmethod
    def _build_evidence(item: DetectionInput) -> Evidence:
        """Assemble the minimal backing evidence for a single input.

        The evidence terminates the audit chain at observed bytes: it
        references the triggering comparison, the baseline captured exchange,
        and the replay (request, result) pair.
        """
        return Evidence(
            comparison_ref=item.comparison.comparison_id,
            captured_exchange_refs=(item.baseline_exchange.exchange_id,),
            replay_pairs=(
                (item.replay_request.request_id, item.replay_result.result_id),
            ),
        )

    def detect_one(self, item: DetectionInput) -> tuple[Finding, ...]:
        """Evaluate all rules against a single input.

        Returns the findings produced for this input (zero or more), in
        deterministic rule order.
        """
        findings: list[Finding] = []
        evidence: Evidence | None = None
        for rule in self._rules:
            match = rule.evaluate(item)
            if match is None:
                continue
            # Build evidence lazily: only inputs that actually match incur it,
            # and all matches for one input share the same backing evidence.
            if evidence is None:
                evidence = self._build_evidence(item)
            findings.append(
                Finding.create(
                    rule_id=match.rule_id,
                    owasp_class=match.owasp_class,
                    severity=match.severity,
                    subject=match.subject,
                    evidence=[evidence],
                )
            )
        return tuple(findings)

    def detect(self, items: Iterable[DetectionInput]) -> tuple[Finding, ...]:
        """Evaluate all rules across many inputs and return unique findings.

        Findings are de-duplicated by ``finding_id`` and returned sorted by
        ``finding_id`` for a stable, reproducible result set.
        """
        by_id: dict[str, Finding] = {}
        for item in items:
            for finding in self.detect_one(item):
                by_id[finding.finding_id] = finding
        return tuple(by_id[key] for key in sorted(by_id))
