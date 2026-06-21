"""Runtime capture configuration.

``CaptureConfig`` holds *runtime* knobs -- principally how to treat sensitive
headers -- and is intentionally **not** part of any content-addressed
artifact. It lets an operator keep credentials and secrets out of persisted
deterministic records (architecture: keep secrets separate from artifacts
where practical) while preserving determinism: the same config applied to the
same traffic always yields the same :class:`~charon.model.CapturedExchange`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

__all__ = ["HeaderAction", "CaptureConfig"]

#: Placeholder written in place of a redacted header value.
REDACTED_PLACEHOLDER = "<redacted>"

#: Headers commonly carrying credentials/secrets, redacted by default.
DEFAULT_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
)


class HeaderAction(enum.Enum):
    """What to do with a sensitive header when building the artifact."""

    #: Keep the header name but replace its value with a fixed placeholder.
    REDACT = "redact"
    #: Drop the header (name and value) entirely.
    DROP = "drop"
    #: Keep the header verbatim (only sensible for non-secret headers).
    KEEP = "keep"


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """Runtime configuration for the recorder.

    Not persisted and not content-addressed. Because the policy is
    deterministic, identical traffic processed under an identical config
    yields identical artifacts.

    :param sensitive_headers: Header names (case-insensitive) treated as
        sensitive.
    :param sensitive_header_action: How to treat sensitive headers when
        producing the persisted artifact.
    """

    sensitive_headers: frozenset[str] = field(
        default_factory=lambda: DEFAULT_SENSITIVE_HEADERS
    )
    sensitive_header_action: HeaderAction = HeaderAction.REDACT

    def __post_init__(self) -> None:
        # Normalize header names to lower-case so matching is case-insensitive
        # and the config behaves deterministically regardless of input casing.
        object.__setattr__(
            self,
            "sensitive_headers",
            frozenset(name.lower() for name in self.sensitive_headers),
        )

    def is_sensitive(self, header_name: str) -> bool:
        """Return ``True`` if ``header_name`` is configured as sensitive."""
        return header_name.lower() in self.sensitive_headers
