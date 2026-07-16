"""The pipeline engine: orchestrate the deterministic core stages.

:class:`Pipeline` wires capture -> replay -> compare -> detect -> report
in a single deterministic run. It is the primary public API for running
Charon end-to-end.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from charon.compare import ComparisonEngine
from charon.detect import DetectionEngine, DetectionInput, default_rules
from charon.model import (
    CapturedExchange,
    Comparison,
    Evidence,
    Finding,
    ReplayRequest,
    ReplayResult,
)
from charon.pipeline.config import PipelineConfig
from charon.replay import (
    ReplayCredential,
    ReplayEngine,
    ReplayExecution,
    Transport,
)
from charon.report import ArtifactIndex, Report, ReportBuilder

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
    :param findings: All unique findings across all inputs, sorted by
        finding_id.
    :param report: The assembled, format-agnostic report.
    """

    artifacts: tuple[PipelineArtifact, ...]
    findings: tuple[Finding, ...]
    report: Report

    @property
    def finding_count(self) -> int:
        return len(self.findings)


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
        4. Indexes all artifacts and builds a deterministic report.

        :param exchanges: Captured exchanges to analyze.
        :param credentials: Credentials to replay each exchange under.
        :returns: A :class:`PipelineResult` with all artifacts, findings,
            and the assembled report.
        """
        artifact_list: list[PipelineArtifact] = []
        detection_inputs: list[DetectionInput] = []

        # Materialize credentials before iterating: an Iterable may be a
        # one-shot iterator that would be exhausted after the first exchange.
        cred_list = tuple(credentials)

        for exchange in exchanges:
            for credential in cred_list:
                artifact = self._process(exchange, credential)
                artifact_list.append(artifact)
                if artifact.detection_input is not None:
                    detection_inputs.append(artifact.detection_input)

        findings = self._detect.detect(detection_inputs)
        index = self._build_index(artifact_list, findings)
        report = ReportBuilder(index=index).build(
            findings,
            mode=self._config.report_mode,
        )
        return PipelineResult(
            artifacts=tuple(artifact_list),
            findings=findings,
            report=report,
        )

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
