"""Assemble the intermediate report model from findings + artifacts.

:class:`ReportBuilder` is read-only: it resolves each finding's references
through an :class:`~charon.report.index.ArtifactIndex`, separates observed
from derived facts by provenance, collects the triggering field diffs, and
builds a stable :class:`~charon.report.model.Report`. It never mutates a
finding or any artifact, never recomputes severity or access decisions, and
never invents prose.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from charon.model import Annotation, Finding, Provenance, Provenanced
from charon.report.index import ArtifactIndex
from charon.report.model import (
    AnnotationView,
    FieldDifference,
    FindingReport,
    ProvenancedFact,
    Report,
    ReportMode,
    TraceReferences,
)

__all__ = ["ReportBuilder"]

_MISSING = "<missing>"


def _fact(name: str, tagged: Provenanced[str]) -> ProvenancedFact:
    return ProvenancedFact(name=name, value=tagged.value, source=tagged.source.value)


class ReportBuilder:
    """Builds a deterministic :class:`~charon.report.model.Report`.

    :param index: Read-only resolver for supporting artifacts.
    """

    def __init__(self, index: ArtifactIndex | None = None) -> None:
        self._index = index if index is not None else ArtifactIndex()

    def build(
        self,
        findings: Iterable[Finding],
        *,
        mode: ReportMode = ReportMode.DETERMINISTIC,
        annotations: Iterable[Annotation] = (),
    ) -> Report:
        """Build a report over ``findings``.

        Findings are sorted by ``finding_id`` for stable output. In
        deterministic mode, ``annotations`` are ignored entirely so no
        Inferred content can appear.
        """
        annotations_by_target = self._group_annotations(mode, annotations)
        reports = [
            self._build_finding(finding, mode, annotations_by_target)
            for finding in findings
        ]
        reports.sort(key=lambda r: r.finding_id)
        return Report(mode=mode, findings=tuple(reports))

    def _group_annotations(
        self, mode: ReportMode, annotations: Iterable[Annotation]
    ) -> Mapping[str, tuple[AnnotationView, ...]]:
        if mode is ReportMode.DETERMINISTIC:
            return {}
        grouped: dict[str, list[AnnotationView]] = {}
        for annotation in annotations:
            # Defensive: only Inferred content may be presented as advisory.
            if annotation.content.source is not Provenance.INFERRED:
                continue
            view = AnnotationView(
                target_ref=annotation.target_ref,
                kind=annotation.kind.value,
                content=annotation.content.value,
                disagrees_with_evidence=annotation.disagrees_with_evidence,
            )
            grouped.setdefault(annotation.target_ref, []).append(view)
        return {
            target: tuple(sorted(views, key=lambda v: (v.kind, v.content)))
            for target, views in grouped.items()
        }

    def _build_finding(
        self,
        finding: Finding,
        mode: ReportMode,
        annotations_by_target: Mapping[str, tuple[AnnotationView, ...]],
    ) -> FindingReport:
        observed: list[ProvenancedFact] = []
        derived: list[ProvenancedFact] = []
        for name in sorted(finding.subject):
            tagged = finding.subject[name]
            fact = _fact(name, tagged)
            if tagged.source is Provenance.DERIVED:
                derived.append(fact)
            else:
                observed.append(fact)

        trace, field_diffs = self._resolve_trace(finding)

        annotations: tuple[AnnotationView, ...] = ()
        if mode is ReportMode.ENRICHED:
            collected: list[AnnotationView] = []
            collected.extend(annotations_by_target.get(finding.finding_id, ()))
            for ev_id in finding.evidence_ids:
                collected.extend(annotations_by_target.get(ev_id, ()))
            annotations = tuple(
                sorted(collected, key=lambda v: (v.target_ref, v.kind, v.content))
            )

        return FindingReport(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            owasp_class=finding.owasp_class.value,
            severity=finding.severity.value,
            title=self._title(finding),
            summary=self._summary(finding),
            observed_facts=tuple(observed),
            derived_facts=tuple(derived),
            field_differences=field_diffs,
            trace=trace,
            annotations=annotations,
        )

    def _resolve_trace(
        self, finding: Finding
    ) -> tuple[TraceReferences, tuple[FieldDifference, ...]]:
        """Walk the finding's evidence to collect refs and triggering diffs."""
        comparison_ids: set[str] = set()
        request_ids: set[str] = set()
        result_ids: set[str] = set()
        exchange_ids: set[str] = set()
        diffs: dict[str, FieldDifference] = {}

        for evidence in finding.evidence:
            comparison_ids.add(evidence.comparison_ref)
            exchange_ids.update(evidence.captured_exchange_refs)
            for request_ref, result_ref in evidence.replay_pairs:
                request_ids.add(request_ref)
                result_ids.add(result_ref)
            comparison = self._index.comparison(evidence.comparison_ref)
            if comparison is not None:
                for diff in comparison.field_diffs:
                    diffs[diff.location] = FieldDifference(
                        location=diff.location,
                        baseline_value=diff.baseline_value,
                        other_value=diff.other_value,
                    )

        trace = TraceReferences(
            evidence_ids=tuple(sorted(finding.evidence_ids)),
            comparison_ids=tuple(sorted(comparison_ids)),
            replay_request_ids=tuple(sorted(request_ids)),
            replay_result_ids=tuple(sorted(result_ids)),
            captured_exchange_ids=tuple(sorted(exchange_ids)),
        )
        field_diffs = tuple(diffs[key] for key in sorted(diffs))
        return trace, field_diffs

    @staticmethod
    def _subject_value(finding: Finding, name: str) -> str:
        tagged = finding.subject.get(name)
        return tagged.value if tagged is not None else _MISSING

    def _title(self, finding: Finding) -> str:
        """Build a defensible title from deterministic subject fields only."""
        method = self._subject_value(finding, "method")
        url = self._subject_value(finding, "url")
        return f"{finding.owasp_class.value} {finding.severity.value}: {method} {url}"

    def _summary(self, finding: Finding) -> str:
        """Build a defensible, mechanical summary from subject fields only.

        The summary restates observed/derived facts; it never speculates
        about intent, ownership, or impact beyond what the artifacts show.
        """
        method = self._subject_value(finding, "method")
        url = self._subject_value(finding, "url")
        baseline_account = self._subject_value(finding, "baseline_account")
        replay_identity = self._subject_value(finding, "replay_identity")
        baseline_decision = self._subject_value(finding, "baseline_decision")
        replay_decision = self._subject_value(finding, "replay_decision")
        return (
            f"Rule {finding.rule_id} matched for {method} {url}. "
            f"Baseline account {baseline_account!r} observed access "
            f"{baseline_decision!r}; replay identity {replay_identity!r} "
            f"observed access {replay_decision!r}."
        )
