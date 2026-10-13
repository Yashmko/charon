"""Declarative endpoint policies for intentional public/role-restricted access.

Policies are explicit, deterministic suppressions. A configured endpoint match
means the caller has declared its access behavior intentional; matching
findings are omitted from the findings list and surfaced as
``policy-declared`` report entries instead.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

__all__ = ["EndpointAccess", "EndpointPolicy", "EndpointPolicyConfig"]

_PARAMETER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}\Z")


class EndpointAccess(enum.Enum):
    """Declared access style for an endpoint."""

    PUBLIC = "public"
    ROLE_RESTRICTED = "role-restricted"


@dataclass(frozen=True, slots=True)
class EndpointPolicy:
    """Declare an intentional endpoint access policy.

    ``path`` is an absolute URL path or a route template whose parameters are
    whole path segments in ``{name}`` form. Role names are recorded as policy
    metadata; Charon does not infer roles from credential labels or validate
    the application's role enforcement.
    """

    method: str
    path: str
    access: EndpointAccess
    allowed_roles: tuple[str, ...] = ()
    description: str = ""
    _compiled_path: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _literal_segments: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.method, str):
            raise ValueError("Endpoint policy method must be a string.")
        method = self.method.strip().upper()
        if not method or any(char.isspace() for char in method):
            raise ValueError("Endpoint policy method must be a non-empty token.")
        object.__setattr__(self, "method", method)

        if not isinstance(self.path, str):
            raise ValueError("Endpoint policy path must be a string.")
        path = self.path.strip()
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or "\\" in path
        ):
            raise ValueError(
                "Endpoint policy path must be an absolute URL path without "
                "query, fragment, or backslash."
            )
        object.__setattr__(self, "path", path)

        try:
            access = EndpointAccess(self.access)
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(access.value for access in EndpointAccess)
            raise ValueError(
                f"Unknown endpoint access policy {self.access!r}; "
                f"expected one of: {allowed}."
            ) from exc
        object.__setattr__(self, "access", access)

        if not isinstance(self.allowed_roles, (tuple, list)) or any(
            not isinstance(role, str) for role in self.allowed_roles
        ):
            raise ValueError("Endpoint policy roles must be a sequence of strings.")
        roles = tuple(sorted({role.strip() for role in self.allowed_roles}))
        if any(not role for role in roles):
            raise ValueError("Endpoint policy roles must be non-empty strings.")
        if access is EndpointAccess.PUBLIC and roles:
            raise ValueError("Public endpoint policies must not declare roles.")
        if access is EndpointAccess.ROLE_RESTRICTED and not roles:
            raise ValueError(
                "Role-restricted endpoint policies require at least one allowed role."
            )
        object.__setattr__(self, "allowed_roles", roles)

        if not isinstance(self.description, str):
            raise ValueError("Endpoint policy description must be a string.")

        segments = path.split("/")
        regex_segments: list[str] = []
        literal_segments = 0
        for segment in segments:
            if _PARAMETER.fullmatch(segment):
                regex_segments.append("[^/]+")
            elif "{" in segment or "}" in segment:
                raise ValueError(
                    "Endpoint path parameters must occupy a whole segment "
                    "and use {name} syntax."
                )
            else:
                regex_segments.append(re.escape(segment))
                if segment:
                    literal_segments += 1
        object.__setattr__(
            self,
            "_compiled_path",
            re.compile("^" + "/".join(regex_segments) + "$"),
        )
        object.__setattr__(self, "_literal_segments", literal_segments)

    def matches(self, method: str, path: str) -> bool:
        """Return whether a method and URL path match this declaration."""
        return (
            method.upper() == self.method
            and self._compiled_path.fullmatch(path) is not None
        )


@dataclass(frozen=True, slots=True)
class EndpointPolicyConfig:
    """Immutable policy set; an empty instance leaves detection unchanged."""

    policies: tuple[EndpointPolicy, ...] = ()

    def __post_init__(self) -> None:
        policies = tuple(self.policies)
        if any(not isinstance(policy, EndpointPolicy) for policy in policies):
            raise TypeError("EndpointPolicyConfig accepts EndpointPolicy entries only.")
        keys = [(policy.method, policy.path) for policy in policies]
        if len(keys) != len(set(keys)):
            raise ValueError("Endpoint policy method/path pairs must be unique.")
        object.__setattr__(
            self,
            "policies",
            tuple(
                sorted(
                    policies,
                    key=lambda policy: (
                        policy.method,
                        -policy._literal_segments,
                        -len(policy.path),
                        policy.path,
                        policy.access.value,
                        policy.allowed_roles,
                    ),
                )
            ),
        )

    def match(self, method: str, path: str) -> EndpointPolicy | None:
        """Return the most specific matching policy, or ``None``.

        Exact/static path segments take precedence over route parameters. All
        remaining ties are resolved by stable lexical ordering.
        """
        matches = [
            policy for policy in self.policies if policy.matches(method, path)
        ]
        if not matches:
            return None
        return min(
            matches,
            key=lambda policy: (
                -policy._literal_segments,
                -len(policy.path),
                policy.path,
                policy.access.value,
            ),
        )
