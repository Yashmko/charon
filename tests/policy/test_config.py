"""Tests for declarative endpoint-policy configuration and matching."""

from __future__ import annotations

import pytest
from charon.policy import EndpointAccess, EndpointPolicy, EndpointPolicyConfig


def test_public_policy_matches_method_and_route_template() -> None:
    policy = EndpointPolicy(
        method="get",
        path="/users/{user_id}/profile",
        access=EndpointAccess.PUBLIC,
    )

    assert policy.method == "GET"
    assert policy.matches("GET", "/users/42/profile")
    assert not policy.matches("POST", "/users/42/profile")
    assert not policy.matches("GET", "/users/42/profile/avatar")


def test_role_restricted_policy_requires_and_sorts_roles() -> None:
    policy = EndpointPolicy(
        method="DELETE",
        path="/accounts/{account_id}",
        access="role-restricted",  # type: ignore[arg-type]
        allowed_roles=("owner", "admin", "admin"),
    )

    assert policy.access is EndpointAccess.ROLE_RESTRICTED
    assert policy.allowed_roles == ("admin", "owner")


def test_invalid_access_declarations_are_rejected() -> None:
    with pytest.raises(ValueError, match="require at least one allowed role"):
        EndpointPolicy(
            method="GET",
            path="/private",
            access=EndpointAccess.ROLE_RESTRICTED,
        )

    with pytest.raises(ValueError, match="must not declare roles"):
        EndpointPolicy(
            method="GET",
            path="/public",
            access=EndpointAccess.PUBLIC,
            allowed_roles=("admin",),
        )


def test_invalid_path_templates_are_rejected() -> None:
    with pytest.raises(ValueError, match="absolute URL path"):
        EndpointPolicy("GET", "users/{id}", EndpointAccess.PUBLIC)

    with pytest.raises(ValueError, match="whole segment"):
        EndpointPolicy("GET", "/users/{id}.json", EndpointAccess.PUBLIC)

    with pytest.raises(ValueError, match="query, fragment"):
        EndpointPolicy("GET", "/users?include=profile", EndpointAccess.PUBLIC)


def test_config_prefers_static_path_over_template() -> None:
    template = EndpointPolicy(
        "GET",
        "/users/{user_id}",
        EndpointAccess.PUBLIC,
    )
    exact = EndpointPolicy(
        "GET",
        "/users/current",
        EndpointAccess.ROLE_RESTRICTED,
        allowed_roles=("user",),
    )
    config = EndpointPolicyConfig((template, exact))

    assert config.match("GET", "/users/current") is exact
    assert config.match("GET", "/users/42") is template
    assert config.match("DELETE", "/users/42") is None


def test_duplicate_policy_routes_are_rejected() -> None:
    public = EndpointPolicy("GET", "/status", EndpointAccess.PUBLIC)
    with pytest.raises(ValueError, match="must be unique"):
        EndpointPolicyConfig((public, public))


def test_empty_policy_config_is_a_noop() -> None:
    assert EndpointPolicyConfig().policies == ()
    assert EndpointPolicyConfig().match("GET", "/anything") is None
