"""Exceptions raised by the Charon core model."""

from __future__ import annotations

__all__ = ["ModelError", "InvalidFindingError", "ProvenanceError"]


class ModelError(Exception):
    """Base class for all errors raised by the core model."""


class InvalidFindingError(ModelError):
    """Raised when an attempt is made to construct an invalid ``Finding``.

    The canonical case is a finding with no associated evidence, which the
    architecture requires to be rejected by the type system rather than by
    convention (see ``docs/data-model.md``).
    """


class ProvenanceError(ModelError):
    """Raised when a value carries provenance that is not permitted.

    For example, a deterministic core field tagged ``Inferred`` (LLM-sourced)
    is rejected: LLM output is advisory only and may never become proof.
    """
