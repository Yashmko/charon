"""Deterministic orchestration for Charon's v1 pipeline.

The ``pipeline`` module wires the existing deterministic stages together:

    capture -> replay -> compare -> detect -> endpoint policy -> report

It enforces ordering, handles transport failures explicitly without
fabricating results, and collects all intermediate artifacts so the
full traceability chain is preserved.

Design goals (see ``docs/architecture.md`` -> ``pipeline``):

* Applies explicit endpoint policy declarations after deterministic detection.
  Matching findings are suppressed and recorded as ``policy-declared``;
  the empty default preserves existing detection behavior.
* Seals the finding set before any enrichment runs.
* Completes successfully whether or not the LLM is available.

Policy declarations are caller-supplied trust decisions, not automatic
validation of the declared access control. This module deliberately does
*not* include CLI parsing, LLM enrichment, or non-deterministic orchestration.
"""

from charon.pipeline.config import PipelineConfig
from charon.pipeline.engine import Pipeline, PipelineArtifact, PipelineResult

__all__ = [
    "Pipeline",
    "PipelineArtifact",
    "PipelineConfig",
    "PipelineResult",
]
