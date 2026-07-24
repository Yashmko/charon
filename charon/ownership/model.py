"""Ownership inference data types.

An :class:`OwnershipInference` records a deterministic determination that a
specific account owns a resource (identified by URL). Inferences are built
from captured exchange response bodies by scanning for owner-related fields.
"""

from __future__ import annotations

from dataclasses import dataclass

from charon.model.addressing import ContentAddress

__all__ = ["OwnershipInference", "OwnershipMap"]


@dataclass(frozen=True, slots=True)
class OwnershipInference:
    """A deterministic inference that an account owns a resource.

    :param url: Normalized URL of the resource whose ownership was inferred.
    :param owning_account: The account label inferred as the resource owner.
    :param source_field: The JSON response field path where the owner reference
        was found (e.g. ``"body.owner_id"``).
    :param source_exchange_id: Content address of the captured exchange that
        produced this inference (traceability back to observed bytes).
    :param confidence: Deterministic confidence score in ``[0.0, 1.0]``.
    """

    url: str
    owning_account: str
    source_field: str
    source_exchange_id: ContentAddress
    confidence: float = 0.85


@dataclass(frozen=True, slots=True)
class OwnershipMap:
    """Immutable collection of ownership inferences.

    Provides stable lookup methods for deterministic rule evaluation and
    reporting. Inferences are sorted by URL then owning account for
    reproducible iteration.
    """

    inferences: tuple[OwnershipInference, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "inferences",
            tuple(
                sorted(
                    self.inferences,
                    key=lambda i: (i.url, i.owning_account, i.source_field),
                )
            ),
        )

    @property
    def count(self) -> int:
        """Number of ownership inferences in the map."""
        return len(self.inferences)

    def owner_of(self, url: str) -> str | None:
        """Return the owning account for ``url``, or ``None`` if unknown.

        When multiple inferences exist for the same URL, the one with the
        highest confidence wins.
        """
        candidates = [i for i in self.inferences if i.url == url]
        if not candidates:
            return None
        best = max(candidates, key=lambda i: i.confidence)
        return best.owning_account

    def is_account_owner(self, url: str, account: str) -> bool | None:
        """Return whether ``account`` owns the resource at ``url``.

        Returns ``True`` / ``False`` when the map has a relevant inference,
        or ``None`` when ownership is unknown (no inference for that URL).
        """
        owner = self.owner_of(url)
        if owner is None:
            return None
        return owner == account

    def resources_owned_by(
        self, account: str
    ) -> tuple[OwnershipInference, ...]:
        """Return all inferences where ``account`` is the owner."""
        return tuple(i for i in self.inferences if i.owning_account == account)
