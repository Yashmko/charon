"""Provenance tagging for every value carried by the core model.

Provenance is mandatory (architecture invariant 5). Every field in a finding
and every annotation carries a source tag, and reports must be able to render
with all ``Inferred`` content stripped.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Generic, TypeVar

__all__ = ["Provenance", "Provenanced"]

T = TypeVar("T")


class Provenance(enum.Enum):
    """Where a value came from.

    The ordering of members is meaningful only as documentation; trust
    decisions are made explicitly, never by comparing enum values.
    """

    #: Captured directly from real traffic.
    OBSERVED = "observed"
    #: Produced by a replayed request issued by Charon.
    REPLAYED = "replayed"
    #: Produced by deterministic computation over observed/replayed data.
    DERIVED = "derived"
    #: Produced by the LLM. Advisory only; never proof.
    INFERRED = "inferred"

    @property
    def is_advisory(self) -> bool:
        """Return ``True`` if this provenance is advisory (LLM-sourced).

        Advisory values must be strippable from a report without affecting
        the deterministic result.
        """
        return self is Provenance.INFERRED

    @property
    def is_deterministic(self) -> bool:
        """Return ``True`` if this provenance is part of the deterministic core."""
        return self is not Provenance.INFERRED


#: Provenance values permitted on the core fields of deterministic artifacts.
DETERMINISTIC_PROVENANCE: frozenset[Provenance] = frozenset(
    {Provenance.OBSERVED, Provenance.REPLAYED, Provenance.DERIVED}
)


@dataclass(frozen=True, slots=True)
class Provenanced(Generic[T]):
    """An immutable value paired with the :class:`Provenance` that produced it.

    Wrapping values this way makes the provenance requirement structural: a
    reader can mechanically separate proven observation from advisory
    suggestion, and a report can strip every ``Inferred`` value generically.
    """

    value: T
    source: Provenance

    @property
    def is_advisory(self) -> bool:
        """Return ``True`` if the wrapped value is advisory (LLM-sourced)."""
        return self.source.is_advisory

    @classmethod
    def observed(cls, value: T) -> "Provenanced[T]":
        """Tag ``value`` as captured directly from real traffic."""
        return cls(value, Provenance.OBSERVED)

    @classmethod
    def replayed(cls, value: T) -> "Provenanced[T]":
        """Tag ``value`` as produced by a Charon-issued replay."""
        return cls(value, Provenance.REPLAYED)

    @classmethod
    def derived(cls, value: T) -> "Provenanced[T]":
        """Tag ``value`` as produced by deterministic computation."""
        return cls(value, Provenance.DERIVED)

    @classmethod
    def inferred(cls, value: T) -> "Provenanced[T]":
        """Tag ``value`` as LLM-produced (advisory only)."""
        return cls(value, Provenance.INFERRED)
