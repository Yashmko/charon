"""Deterministic configuration for the ownership inference engine.

All knobs are fixed, declarative rule sets -- never heuristics or learned
behavior. The same config applied to the same exchanges always yields
identical ownership inferences.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["OwnershipConfig"]

OWNER_FIELD_PATTERNS: frozenset[str] = frozenset(
    {
        "owner_id",
        "owner",
        "user_id",
        "userid",
        "account_id",
        "customer_id",
        "created_by",
        "belongs_to",
        "userId",
        "ownerId",
        "accountId",
        "customerId",
        "user_uuid",
        "owner_uuid",
    }
)


@dataclass(frozen=True, slots=True)
class OwnershipConfig:
    """Deterministic configuration for the OwnershipEngine.

    :param owner_field_patterns: Response JSON field names (case-insensitive
        matching) whose values are interpreted as owner account references.
    :param owner_confidence: Confidence assigned to direct field-value matches
        where the field value equals the exchange's account label.
    :param account_label_confidence: Confidence assigned when an account label
        appears as a top-level value anywhere in the response body.
    :param min_confidence: Minimum confidence required to include an
        inference in the output map.
    """

    owner_field_patterns: frozenset[str] = field(
        default_factory=lambda: OWNER_FIELD_PATTERNS
    )
    owner_confidence: float = 0.85
    account_label_confidence: float = 0.6
    min_confidence: float = 0.5

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "owner_field_patterns",
            frozenset(p.lower() for p in self.owner_field_patterns),
        )

    def is_owner_field(self, field_name: str) -> bool:
        """Return ``True`` if ``field_name`` matches a configured owner pattern."""
        return field_name.lower() in self.owner_field_patterns
