"""Deterministic orchestration for Charon's v1 pipeline.

The ``pipeline`` module wires the existing deterministic stages together:

    capture -> replay -> compare -> detect -> report

It enforces ordering, handles transport failures explicitly without
fabricating results, and collects all intermediate artifacts so the
full traceability chain is preserved.

Design goals (see ``docs/architecture.md`` -> ``pipeline``):

* Seals the finding set before any enrichment runs.
* Completes successfully whether or not the LLM is available (always
  runs in deterministic mode for v1).
* Never creates, modifies, suppresses, or infers findings.

This module deliberately does *not* include CLI parsing, LLM enrichment,
or any non-deterministic orchestration.
"""

from charon.pipeline.config import PipelineConfig
from charon.pipeline.engine import Pipeline, PipelineArtifact, PipelineResult

__all__ = [
    "Pipeline",
    "PipelineArtifact",
    "PipelineConfig",
    "PipelineResult",
]
