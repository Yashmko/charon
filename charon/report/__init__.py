"""Deterministic, read-only reporting for Charon.

The ``report`` module converts already-generated
:class:`~charon.model.Finding` objects and their supporting artifacts
(:class:`~charon.model.Evidence`, :class:`~charon.model.Comparison`,
:class:`~charon.model.ReplayRequest` / :class:`~charon.model.ReplayResult`,
:class:`~charon.model.CapturedExchange`) into structured, human-readable
reports.

Design goals (see ``docs/architecture.md`` -> ``report`` acceptance
criteria):

* Renders a complete deterministic report with all inferred annotations
  disabled.
* Deterministic-mode output never contains LLM-sourced content.
* Enriched mode overlays advisory annotations without altering deterministic
  content.
* Byte-for-byte identical output for identical inputs.

The reporting layer is **presentation only**: it never creates, modifies,
suppresses, upgrades, downgrades, or infers findings, never recomputes
severity or access decisions, and never consults an LLM.
"""

from charon.report.builder import ReportBuilder
from charon.report.index import ArtifactIndex
from charon.report.json_renderer import render_json
from charon.report.markdown import render_markdown
from charon.report.model import (
    FindingReport,
    Report,
    ReportMode,
    TraceReferences,
)

__all__ = [
    "ArtifactIndex",
    "FindingReport",
    "Report",
    "ReportBuilder",
    "ReportMode",
    "TraceReferences",
    "render_json",
    "render_markdown",
]
