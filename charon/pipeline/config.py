"""Deterministic pipeline configuration.

``PipelineConfig`` bundles the configs for downstream stages so the
pipeline can be configured from a single point. All config is
deterministic and declarative.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from charon.compare import ComparisonConfig
from charon.detect import RuleConfig
from charon.ownership import OwnershipConfig
from charon.policy import EndpointPolicyConfig
from charon.report import ReportMode

__all__ = ["PipelineConfig"]


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Deterministic configuration for the full pipeline.

    :param comparison: Configuration for the comparison engine (volatile
        fields, max body size for structured diff).
    :param ownership: Configuration for the ownership inference engine
        (owner-field patterns, confidence thresholds).
    :param rules: Configuration for the detection rules (enablement,
        severities).
    :param report_mode: Whether to include advisory annotations in the
        report. Defaults to DETERMINISTIC (no inferred content).
    :param transport_timeout_seconds: Per-request timeout passed to the
        replay transport.
    :param transport_follow_redirects: Whether the transport should follow
        redirects during replay.
    :param endpoint_policy: Explicit endpoint declarations for intentionally
        public or role-restricted access. Empty by default.
    """

    comparison: ComparisonConfig = field(default_factory=ComparisonConfig)
    ownership: OwnershipConfig = field(default_factory=OwnershipConfig)
    rules: RuleConfig = field(default_factory=RuleConfig)
    report_mode: ReportMode = ReportMode.DETERMINISTIC
    transport_timeout_seconds: float = 30.0
    transport_follow_redirects: bool = False
    endpoint_policy: EndpointPolicyConfig = field(
        default_factory=EndpointPolicyConfig
    )
