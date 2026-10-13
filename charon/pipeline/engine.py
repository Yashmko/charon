"""The pipeline engine: orchestrate the deterministic core stages.

:class:`Pipeline` wires capture -> replay -> compare -> detect -> endpoint
policy -> report in a single deterministic run. An empty endpoint policy
preserves the existing detection flow; explicit matches are reported as
``policy-declared`` instead of findings.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from charon.compare import ComparisonEngine
from charon.detect import (
    DetectionEngine,
    DetectionInput,
    default_rules,
    score_findings,
)
from charon.model import (
    CapturedExchange,
    Comparison,
    Evidence,
    Finding,
    ReplayRequest,
    ReplayResult,
)
from charon.ownership import OwnershipEngine, OwnershipMap
from charon.pipeline.config import PipelineConfig
from charon.policy import EndpointPolicy
from charon.replay import (
    ReplayCredential,
    ReplayEngine,
    ReplayExecution,
    Transport,
)
from charon.report import (
    ArtifactIndex,
    PolicyDeclarationView,
    Report,
    ReportBuilder,
    SuppressedFindingView,
)

__all__ = ["PipelineArtifact", "PipelineResult", "Pipeline"]


@dataclass(frozen=True, slots=True)
class PipelineArtifact:
    """One exchange processed through the pipeline.

    Every artifact created for a single (exchange, credential) pair is
    collected here so callers and the report builder have full traceability.
    """

    exchange: CapturedExchange
    credential: ReplayCredential
    execution: ReplayExecution
    comparison: Comparison | None = None
    detection_input: DetectionInput | None = None


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """The complete output of a pipeline run.

    :param artifacts: Per-exchange pipeline artifacts, preserving the full
        traceability chain.
    :param findings: Unique findings not suppressed by an explicit endpoint
        policy, sorted by finding_id.
    :param ownership: Ownership map inferred from captured exchanges.
    :param report: The assembled, format-agnostic report.
    """

    artifacts: tuple[PipelineArtifact, ...]
    findings: tuple[Finding, ...]
    ownership: OwnershipMap
    report: Report

    @property
    def finding_count(self) -> int:
        return len(self.findings)


@dataclass(slots=True)
class _PolicyDeclarationAccumulator:
    policy: EndpointPolicy
    method: str
    path: str
    matched_exchange_ids: set[str] = field(default_factory=set)
    suppressed_findings: dict[str, SuppressedFindingView] = field(default_factory=dict)


class Pipeline:
    """Orchestrate the deterministic core stages end-to-end.

    :param transport: The transport used to issue replay requests. Must
        satisfy the :class:`~charon.replay.transport.Transport` protocol.
    :param config: Pipeline configuration. Defaults to sensible defaults.
    """

    def __init__(
        self,
        transport: Transport,
        config: PipelineConfig | None = None,
    ) -> None:
        cfg = config if config is not None else PipelineConfig()
        self._replay = ReplayEngine(
            transport=transport,
            follow_redirects=cfg.transport_follow_redirects,
            timeout_seconds=cfg.transport_timeout_seconds,
        )
        self._compare = ComparisonEngine(config=cfg.comparison)
        self._ownership = OwnershipEngine(config=cfg.ownership)
        self._detect = DetectionEngine(
            rules=default_rules(config=cfg.rules)
        )
        # ReportBuilder is created per-run with the correct artifact index.
        # No persistent instance needed here.
        self._config = cfg

    @property
    def config(self) -> PipelineConfig:
        return self._config

    def run(
        self,
        exchanges: Iterable[CapturedExchange],
        credentials: Iterable[ReplayCredential],
    ) -> PipelineResult:
        """Run the full pipeline over ``exchanges`` with ``credentials``.

        For each (exchange, credential) pair where the credential label
        differs from the exchange's account label, the pipeline:

        1. Replays the exchange under the credential.
        2. Compares the replay response to the baseline.
        3. Runs detection rules over the comparison.
        4. Applies any explicit endpoint policies; matched signals are
           reported as ``policy-declared`` rather than findings.
        5. Indexes artifacts and builds a deterministic report.

        :param exchanges: Captured exchanges to analyze.
        :param credentials: Credentials to replay each exchange under.
        :returns: A :class:`PipelineResult` with all artifacts, findings,
            and the assembled report.
        """
        exchange_list = tuple(exchanges)
        artifact_list: list[PipelineArtifact] = []
        detection_inputs: list[DetectionInput] = []

        # Materialize credentials before iterating: an Iterable may be a
        # one-shot iterator that would be exhausted after the first exchange.
        cred_list = tuple(credentials)

        # Run ownership inference over all captured exchanges before replay.
        ownership = self._ownership.analyze(exchange_list)

        for exchange in exchange_list:
            for credential in cred_list:
                artifact = self._process(exchange, credential)
                artifact_list.append(artifact)
                if artifact.detection_input is not None:
                    detection_inputs.append(artifact.detection_input)

        detected_findings = self._detect.detect(
            detection_inputs, ownership=ownership
        )
        findings, policy_declarations = self._apply_endpoint_policies(
            exchange_list, detected_findings
        )
        index = self._build_index(artifact_list, findings)
        confidence_scores = score_findings(
            findings,
            tuple(detection_inputs),
            self._config.rules,
        )
        report = ReportBuilder(index=index).build(
            findings,
            mode=self._config.report_mode,
            confidence_scores=confidence_scores,
            ownership=ownership,
            policy_declarations=policy_declarations,
        )
        return PipelineResult(
            artifacts=tuple(artifact_list),
            findings=findings,
            ownership=ownership,
            report=report,
        )

    def _apply_endpoint_policies(
        self,
        exchanges: tuple[CapturedExchange, ...],
        findings: tuple[Finding, ...],
    ) -> tuple[tuple[Finding, ...], tuple[PolicyDeclarationView, ...]]:
        """Suppress findings fully covered by an explicit endpoint policy.

        A finding is suppressed only when every captured exchange in its
        evidence chain matches a declared policy. This keeps cross-endpoint
        matrix findings visible if any supporting endpoint is undeclared.
        """
        policy_config = self._config.endpoint_policy
        if not policy_config.policies:
            return findings, ()

        matches_by_exchange: dict[
            str, tuple[EndpointPolicy, str, str]
        ] = {}
        accumulators: dict[
            tuple[EndpointPolicy, str, str], _PolicyDeclarationAccumulator
        ] = {}

        def accumulator_for(
            policy: EndpointPolicy,
            method: str,
            path: str,
        ) -> _PolicyDeclarationAccumulator:
            key = (policy, method, path)
            if key not in accumulators:
                accumulators[key] = _PolicyDeclarationAccumulator(
                    policy=policy,
                    method=method,
                    path=path,
                )
            return accumulators[key]

        for exchange in exchanges:
            path = urlsplit(exchange.url).path
            policy = policy_config.match(exchange.method, path)
            if policy is None:
                continue
            matches_by_exchange[exchange.exchange_id] = (
                policy,
                exchange.method,
                path,
            )
            accumulator_for(policy, exchange.method, path).matched_exchange_ids.add(
                exchange.exchange_id
            )

        retained_findings: list[Finding] = []
        for finding in findings:
            exchange_ids = sorted(
                {
                    exchange_id
                    for evidence in finding.evidence
                    for exchange_id in evidence.captured_exchange_refs
                }
            )
            policy_matches = [
                matches_by_exchange.get(exchange_id) for exchange_id in exchange_ids
            ]
            if not exchange_ids or any(match is None for match in policy_matches):
                retained_findings.append(finding)
                continue

            suppressed = SuppressedFindingView(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                owasp_class=finding.owasp_class.value,
            )
            for match in policy_matches:
                assert match is not None
                policy, method, path = match
                accumulator_for(policy, method, path).suppressed_findings[
                    finding.finding_id
                ] = suppressed

        declarations = tuple(
            PolicyDeclarationView(
                method=accumulator.method,
                path=accumulator.path,
                policy_path=accumulator.policy.path,
                access=accumulator.policy.access.value,
                allowed_roles=accumulator.policy.allowed_roles,
                description=accumulator.policy.description,
                matched_exchange_ids=tuple(
                    sorted(accumulator.matched_exchange_ids)
                ),
                suppressed_findings=tuple(
                    accumulator.suppressed_findings[finding_id]
                    for finding_id in sorted(accumulator.suppressed_findings)
                ),
            )
            for _key, accumulator in sorted(
                accumulators.items(),
                key=lambda item: (
                    item[0][1],
                    item[0][2],
                    item[0][0].path,
                    item[0][0].access.value,
                ),
            )
        )
        return tuple(retained_findings), declarations

    def _process(
        self,
        exchange: CapturedExchange,
        credential: ReplayCredential,
    ) -> PipelineArtifact:
        """Process a single (exchange, credential) pair through the stages.

        Transport failures are collected explicitly in the artifact; they
        never fabricate comparison results or findings.
        """
        execution = self._replay.replay(exchange, credential)

        if not execution.succeeded or execution.result is None:
            return PipelineArtifact(
                exchange=exchange,
                credential=credential,
                execution=execution,
            )

        comparison = self._compare.compare(exchange, execution.result)
        detection_input = DetectionInput(
            comparison=comparison,
            baseline_exchange=exchange,
            replay_request=execution.request,
            replay_result=execution.result,
        )
        return PipelineArtifact(
            exchange=exchange,
            credential=credential,
            execution=execution,
            comparison=comparison,
            detection_input=detection_input,
        )

    @staticmethod
    def _build_index(
        artifacts: Iterable[PipelineArtifact],
        findings: tuple[Finding, ...],
    ) -> ArtifactIndex:
        """Build a read-only artifact index for report assembly."""
        exchanges: list[CapturedExchange] = []
        replay_requests: list[ReplayRequest] = []
        replay_results: list[ReplayResult] = []
        comparisons: list[Comparison] = []
        evidence_items: list[Evidence] = []

        for artifact in artifacts:
            exchanges.append(artifact.exchange)
            replay_requests.append(artifact.execution.request)
            if artifact.execution.result is not None:
                replay_results.append(artifact.execution.result)
            if artifact.comparison is not None:
                comparisons.append(artifact.comparison)

        for finding in findings:
            evidence_items.extend(finding.evidence)

        return ArtifactIndex(
            captured_exchanges=exchanges,
            replay_requests=replay_requests,
            replay_results=replay_results,
            comparisons=comparisons,
            evidence=evidence_items,
        )
