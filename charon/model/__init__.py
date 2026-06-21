"""Canonical, deterministic data types for Charon's core.

This package defines the immutable, well-typed core models and the
type-level invariant that a :class:`~charon.model.finding.Finding` cannot be
constructed without at least one :class:`~charon.model.evidence.Evidence`
reference. See ``docs/data-model.md`` and ``docs/architecture.md``.

Architectural invariants enforced (or supported) here:

* **Evidence-backed findings.** A ``Finding`` requires >= 1 evidence
  reference at construction time; this is enforced by the type, not by
  convention.
* **Determinism.** Content addressing uses canonical JSON + SHA-256 with no
  wall-clock, randomness, or network input.
* **LLM is advisory.** ``Annotation`` is the only ``Inferred`` type. It
  attaches by reference and cannot create, modify, suppress, upgrade,
  downgrade, or delete a ``Finding``.
* **Provenance is mandatory.** Every value carried in a finding and every
  annotation is tagged with a :class:`~charon.model.provenance.Provenance`
  source.

This module deliberately contains *no* capture, replay, compare, detect,
report, or LLM logic.
"""

from charon.model.addressing import ContentAddress, content_address
from charon.model.annotation import Annotation
from charon.model.comparison import (
    AccessDecision,
    Comparison,
    FieldDiff,
    ResponseSnapshot,
)
from charon.model.evidence import Evidence
from charon.model.exceptions import (
    InvalidFindingError,
    ModelError,
    ProvenanceError,
)
from charon.model.exchange import CapturedExchange, HttpMessage
from charon.model.finding import Finding, OwaspClass, Severity
from charon.model.provenance import Provenance, Provenanced
from charon.model.replay import ReplayIdentity, ReplayRequest, ReplayResult

__all__ = [
    "AccessDecision",
    "Annotation",
    "CapturedExchange",
    "Comparison",
    "ContentAddress",
    "Evidence",
    "FieldDiff",
    "Finding",
    "HttpMessage",
    "InvalidFindingError",
    "ModelError",
    "OwaspClass",
    "Provenance",
    "Provenanced",
    "ProvenanceError",
    "ReplayIdentity",
    "ReplayRequest",
    "ReplayResult",
    "ResponseSnapshot",
    "Severity",
    "content_address",
]
