"""Deterministic configuration for the comparison engine.

All knobs here are fixed, declarative rule sets -- never heuristics or
learned behavior. Volatile fields are excluded from meaningful diffs by
exact (case-insensitive) name match so that the same inputs and config
always produce the same :class:`~charon.model.Comparison`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["ComparisonConfig"]

#: Response header names whose values are expected to vary run-to-run and
#: carry no access-control signal. Matched case-insensitively.
DEFAULT_VOLATILE_HEADERS: frozenset[str] = frozenset(
    {
        "date",
        "set-cookie",
        "age",
        "expires",
        "etag",
        "last-modified",
        "request-id",
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "cf-ray",
    }
)

#: JSON body key names whose values are expected to vary run-to-run. Matched
#: case-insensitively against the *leaf key name* of a body path.
DEFAULT_VOLATILE_BODY_KEYS: frozenset[str] = frozenset(
    {
        "timestamp",
        "created_at",
        "updated_at",
        "csrf",
        "csrf_token",
        "request_id",
        "requestid",
        "trace_id",
        "nonce",
    }
)


@dataclass(frozen=True, slots=True)
class ComparisonConfig:
    """Runtime configuration for :class:`~charon.compare.engine.ComparisonEngine`.

    :param volatile_headers: Header names excluded from meaningful diffs.
    :param volatile_body_keys: JSON leaf-key names excluded from meaningful
        diffs.
    :param max_body_bytes_for_structured_diff: Bodies larger than this are
        compared by digest only (protects against pathological inputs while
        staying deterministic).
    """

    volatile_headers: frozenset[str] = field(
        default_factory=lambda: DEFAULT_VOLATILE_HEADERS
    )
    volatile_body_keys: frozenset[str] = field(
        default_factory=lambda: DEFAULT_VOLATILE_BODY_KEYS
    )
    max_body_bytes_for_structured_diff: int = 1_048_576

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "volatile_headers",
            frozenset(name.lower() for name in self.volatile_headers),
        )
        object.__setattr__(
            self,
            "volatile_body_keys",
            frozenset(name.lower() for name in self.volatile_body_keys),
        )

    def is_volatile_header(self, name: str) -> bool:
        """Return ``True`` if ``name`` is a configured volatile header."""
        return name.lower() in self.volatile_headers

    def is_volatile_body_key(self, leaf_key: str) -> bool:
        """Return ``True`` if ``leaf_key`` is a configured volatile body key."""
        return leaf_key.lower() in self.volatile_body_keys
