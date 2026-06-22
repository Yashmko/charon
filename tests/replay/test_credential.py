"""Tests for runtime replay credentials and secret handling."""

from __future__ import annotations

from charon.model import ReplayIdentity
from charon.replay import ReplayCredential


def test_identity_is_label_only() -> None:
    cred = ReplayCredential(label="userB", bearer_token="secret")
    assert cred.identity == ReplayIdentity(label="userB")
    # No secret material leaks into the model identity.
    assert "secret" not in cred.identity.to_canonical()["label"]


def test_bearer_token_becomes_authorization_header() -> None:
    cred = ReplayCredential(label="userB", bearer_token="abc")
    assert ("authorization", "Bearer abc") in cred.auth_headers()


def test_cookies_are_joined_into_single_header() -> None:
    cred = ReplayCredential(
        label="userB", cookies=(("sid", "1"), ("csrf", "2"))
    )
    headers = dict(cred.auth_headers())
    assert headers["cookie"] == "sid=1; csrf=2"


def test_api_key_uses_configurable_header() -> None:
    cred = ReplayCredential(
        label="svc", api_key="k", api_key_header="X-Custom-Key"
    )
    headers = dict(cred.auth_headers())
    assert headers["x-custom-key"] == "k"


def test_extra_headers_are_applied() -> None:
    cred = ReplayCredential(
        label="u", extra_headers=(("X-Tenant", "acme"),)
    )
    assert ("x-tenant", "acme") in cred.auth_headers()


def test_applied_header_names_tracks_all_auth_headers() -> None:
    cred = ReplayCredential(
        label="u",
        bearer_token="t",
        cookies=(("sid", "1"),),
        api_key="k",
    )
    names = cred.applied_header_names()
    assert {"authorization", "cookie", "x-api-key"} <= names
