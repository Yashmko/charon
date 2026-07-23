"""Deterministic authorization detection for Charon's core.

The ``detect`` module is the **sole authority that creates findings**
(architecture invariant; see ``docs/architecture.md``). It applies
deterministic rules to :class:`~charon.model.Comparison` artifacts (together
with their source capture/replay context) and emits evidence-backed
:class:`~charon.model.Finding` objects.

Detection philosophy: never guess. A finding is emitted only when the
observable artifacts jointly justify it -- a status transition, an
access-decision transition, the relevant field-level diffs, and the fact that
the replay identity differs from the baseline account. It is better to miss a
questionable issue than to emit a finding that cannot be defended from
concrete evidence.

This module performs no semantic interpretation and uses no LLM. It does not
generate reports, explanations, or the cross-finding evidence chain (that is
the separate ``evidence`` module); it only constructs the minimal
:class:`~charon.model.Evidence` required to back each finding it emits.
"""

from charon.detect.confidence import ConfidenceScorer, score_findings
from charon.detect.engine import DetectionEngine
from charon.detect.input import DetectionInput
from charon.detect.matrix import MatrixAnalysis, MatrixResult
from charon.detect.rules import (
    BflaRule,
    BolaRule,
    Rule,
    RuleConfig,
    RuleMatch,
    default_rules,
)
from charon.detect.rules_bopla import BoplaRule
from charon.detect.rules_missing_authz import MissingAuthzRule

__all__ = [
    "BflaRule",
    "BolaRule",
    "BoplaRule",
    "ConfidenceScorer",
    "DetectionEngine",
    "DetectionInput",
    "MatrixAnalysis",
    "MatrixResult",
    "MissingAuthzRule",
    "Rule",
    "RuleConfig",
    "RuleMatch",
    "default_rules",
    "score_findings",
]
