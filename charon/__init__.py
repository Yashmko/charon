"""Charon: deterministic, evidence-driven authorization analysis.

The deterministic core modules are fully implemented:

* ``model`` — Canonical data types with content-addressing, provenance
  tagging, and evidence-backed Finding construction.
* ``capture`` — Traffic recording from HAR files, raw dicts, and other
  backends, with deterministic normalization and secret handling.
* ``replay`` — HTTP replay engine with pluggable transports, credential
  management, and typed failure recording.
* ``compare`` — Deterministic baseline-vs-replay response comparison
  with structured diffing and access-decision classification.
* ``detect`` — Rule-based authorization detection engine (BOLA, BFLA)
  that produces evidence-backed findings.
* ``report`` — Read-only report assembly with JSON and Markdown
  renderers, supporting deterministic and enriched modes.
* ``pipeline`` — Orchestration that wires the stages together into a
  single deterministic run.
* ``cli`` — Command-line interface for the pipeline.

The advisory layer (LLM enrichment, annotation) is not yet implemented.
See ``docs/architecture.md``, ``docs/v1-scope.md``, and ``docs/data-model.md``
for the locked, canonical v1 design.
"""

from charon import model

__version__ = "0.1.0"
__all__ = ["model"]
