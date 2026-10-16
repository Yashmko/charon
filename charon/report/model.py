"""Intermediate, format-agnostic report model.

The :class:`ReportBuilder` produces these immutable structures, and each
renderer (Markdown, JSON) consumes them. Keeping a single intermediate model
guarantees the two formats describe exactly the same content, and makes
determinism easy to reason about: the model is already fully ordered and
resolved before any text is produced.

Every field here is derived purely from deterministic pipeline artifacts.
The only advisory content is :attr:`FindingReport.annotations`, which is
always clearly separated and omitted entirely in deterministic mode.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

__all__ = [
    "ReportMode",
    "ProvenancedFact",
    "FieldDifference",
    "TraceReferences",
    "AnnotationView",
    "OwnershipView",
    "SuppressedFindingView",
    "PolicyDeclarationView",
    "FindingReport",
    "Report",
]


#: Schema version for the JSON output; bumped only on breaking changes.
REPORT_SCHEMA_VERSION = "2"


class ReportMode(enum.Enum):
    """Whether advisory (Inferred) annotations are included."""

    #: Deterministic only. No Inferred content is ever emitted.
    DETERMINISTIC = "deterministic"
    #: Deterministic skeleton plus advisory annotations, clearly labeled.
    ENRICHED = "enriched"


@dataclass(frozen=True, slots=True)
class ProvenancedFact:
    """A single subject fact, tagged with its deterministic provenance."""

    name: str
    value: str
    source: str


@dataclass(frozen=True, slots=True)
class FieldDifference:
    """A field-level difference that contributed to a finding."""

    location: str
    baseline_value: str | None
    other_value: str | None


@dataclass(frozen=True, slots=True)
class TraceReferences:
    """The walkable audit chain references for one finding.

    All values are content addresses (or ``"<missing>"`` markers when an
    artifact was not supplied to the index), sorted for stable output.
    """

    evidence_ids: tuple[str, ...]
    comparison_ids: tuple[str, ...]
    replay_request_ids: tuple[str, ...]
    replay_result_ids: tuple[str, ...]
    captured_exchange_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnnotationView:
    """An advisory (Inferred) annotation, rendered separately from facts."""

    target_ref: str
    kind: str
    content: str
    disagrees_with_evidence: bool


@dataclass(frozen=True, slots=True)
class OwnershipView:
    """A deterministic ownership inference, rendered for traceability.

    :param url: Normalized URL of the resource whose ownership was inferred.
    :param owning_account: The account determined to own this resource.
    :param source_field: The response JSON field providing the evidence.
    :param confidence: Confidence score for this inference.
    """

    url: str
    owning_account: str
    source_field: str
    confidence: float


@dataclass(frozen=True, slots=True)
class SuppressedFindingView:
    """Identity and classification of a finding suppressed by a policy."""

    finding_id: str
    rule_id: str
    classification: str
    classification_scope: str


@dataclass(frozen=True, slots=True)
class PolicyDeclarationView:
    """An endpoint access declaration matched during this run.

    These entries are not findings. They explain why a matching endpoint was
    excluded from the findings list and retain the suppressed finding IDs for
    auditability.
    """

    method: str
    path: str
    policy_path: str
    access: str
    allowed_roles: tuple[str, ...]
    matched_exchange_ids: tuple[str, ...]
    suppressed_findings: tuple[SuppressedFindingView, ...]
    description: str = ""
    status: str = field(default="policy-declared", init=False)


@dataclass(frozen=True, slots=True)
class FindingReport:
    """The fully-resolved, deterministic presentation of one finding."""

    finding_id: str
    rule_id: str
    classification: str
    classification_scope: str
    severity: str
    confidence: float
    title: str
    summary: str
    observed_facts: tuple[ProvenancedFact, ...]
    derived_facts: tuple[ProvenancedFact, ...]
    field_differences: tuple[FieldDifference, ...]
    trace: TraceReferences
    annotations: tuple[AnnotationView, ...] = ()


@dataclass(frozen=True, slots=True)
class Report:
    """A complete, deterministic report over a set of findings."""

    mode: ReportMode
    findings: tuple[FindingReport, ...]
    ownership: tuple[OwnershipView, ...] = ()
    schema_version: str = field(default=REPORT_SCHEMA_VERSION)
    policy_declarations: tuple[PolicyDeclarationView, ...] = ()

    @property
    def finding_count(self) -> int:
        """Number of findings in the report."""
        return len(self.findings)
