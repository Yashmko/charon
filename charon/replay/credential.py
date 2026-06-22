"""Runtime replay credentials.

A :class:`ReplayCredential` carries the actual authentication material used
to issue a replay (bearer token, cookies, API key, or arbitrary custom
headers) bound to a model :class:`~charon.model.ReplayIdentity` label.

Credentials are **runtime-only**. They are applied to the outgoing transport
request but never stored in the content-addressed ``ReplayRequest`` /
``ReplayResult``: the engine substitutes sensitive header values with a fixed
placeholder before building the persisted artifact. This keeps secrets out of
deterministic records while letting auth be swapped without touching
unrelated request structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from charon.model import ReplayIdentity

__all__ = ["ReplayCredential", "REDACTED_PLACEHOLDER", "SENSITIVE_HEADERS"]

#: Placeholder substituted for sensitive header values in persisted artifacts.
REDACTED_PLACEHOLDER = "<redacted>"

#: Header names (lower-case) considered credential-bearing and thus redacted
#: from persisted artifacts.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
    }
)


@dataclass(frozen=True, slots=True)
class ReplayCredential:
    """Authentication context a replay is issued under (runtime-only).

    :param label: Stable identity label, also used for the model
        :class:`~charon.model.ReplayIdentity`. Non-secret.
    :param bearer_token: Optional bearer token; sets ``Authorization:
        Bearer <token>``.
    :param cookies: Optional cookie name/value pairs; joined into a single
        ``Cookie`` header.
    :param api_key: Optional API key value.
    :param api_key_header: Header name to carry the API key. Defaults to
        ``X-API-Key``.
    :param extra_headers: Arbitrary additional headers (e.g. custom auth).
        Applied verbatim; redacted in artifacts only if the name is sensitive.
    """

    label: str
    bearer_token: str | None = None
    cookies: tuple[tuple[str, str], ...] = ()
    api_key: str | None = None
    api_key_header: str = "X-API-Key"
    extra_headers: tuple[tuple[str, str], ...] = field(default=())

    @property
    def identity(self) -> ReplayIdentity:
        """The model identity (label only, no secrets) for this credential."""
        return ReplayIdentity(label=self.label)

    def auth_headers(self) -> tuple[tuple[str, str], ...]:
        """Return the auth headers this credential contributes.

        Header names follow the order: bearer, cookie, api-key, then any
        extra headers (in the order provided). The result is what gets merged
        onto the outgoing request.
        """
        headers: list[tuple[str, str]] = []
        if self.bearer_token is not None:
            headers.append(("authorization", f"Bearer {self.bearer_token}"))
        if self.cookies:
            cookie_value = "; ".join(f"{k}={v}" for k, v in self.cookies)
            headers.append(("cookie", cookie_value))
        if self.api_key is not None:
            headers.append((self.api_key_header.lower(), self.api_key))
        headers.extend((name.lower(), value) for name, value in self.extra_headers)
        return tuple(headers)

    def applied_header_names(self) -> frozenset[str]:
        """Return the lower-cased names of headers this credential sets."""
        return frozenset(name for name, _ in self.auth_headers())
