"""Tests for the deterministic normalization helpers."""

from __future__ import annotations

from charon.capture import (
    extract_resource_refs,
    normalize_headers,
    normalize_method,
    normalize_query,
    normalize_url,
)


def test_normalize_method_uppercases_and_strips() -> None:
    assert normalize_method(" get ") == "GET"
    assert normalize_method("Post") == "POST"


def test_normalize_url_lowercases_scheme_host_and_strips_default_port() -> None:
    assert (
        normalize_url("HTTPS://API.Example.TEST:443/Path")
        == "https://api.example.test/Path"
    )
    assert (
        normalize_url("http://Host.test:80/x") == "http://host.test/x"
    )
    # Non-default port is preserved.
    assert normalize_url("https://h.test:8443/x") == "https://h.test:8443/x"


def test_normalize_url_sorts_query_and_drops_fragment() -> None:
    assert (
        normalize_url("https://h.test/p?b=2&a=1#frag")
        == "https://h.test/p?a=1&b=2"
    )


def test_normalize_url_is_idempotent() -> None:
    once = normalize_url("HTTPS://H.test:443/p?b=2&a=1")
    assert normalize_url(once) == once


def test_normalize_query_sorts_and_keeps_duplicates() -> None:
    assert normalize_query("b=2&a=1&a=0") == (("a", "0"), ("a", "1"), ("b", "2"))


def test_normalize_headers_lowercases_names_and_sorts() -> None:
    out = normalize_headers((("X-B", "2"), ("Authorization", "x"), ("x-a", "1")))
    assert out == (("authorization", "x"), ("x-a", "1"), ("x-b", "2"))


def test_extract_resource_refs_from_path_and_query() -> None:
    refs = extract_resource_refs(
        path="/api/orders/8821/items/abc-def",
        query=(("ref", "550e8400-e29b-41d4-a716-446655440000"),),
        body=None,
        content_type=None,
    )
    assert ("path", "segment3", "8821") in refs
    assert ("path", "segment5", "abc-def") in refs
    assert ("query", "ref", "550e8400-e29b-41d4-a716-446655440000") in refs


def test_extract_resource_refs_from_json_body() -> None:
    body = b'{"id": 8821, "owner_id": "userA", "nested": {"uuid": "550e8400-e29b-41d4-a716-446655440000"}}'
    refs = extract_resource_refs(
        path="/x",
        query=(),
        body=body,
        content_type="application/json; charset=utf-8",
    )
    assert ("body.id", "id", "8821") in refs
    assert (
        "body.nested.uuid",
        "uuid",
        "550e8400-e29b-41d4-a716-446655440000",
    ) in refs
    # "userA" is not uuid/int/slug, so it is not extracted.
    assert all(value != "userA" for _, _, value in refs)


def test_extract_resource_refs_ignores_non_json_body() -> None:
    refs = extract_resource_refs(
        path="/x",
        query=(),
        body=b"id=8821",
        content_type="text/plain",
    )
    assert refs == ()


def test_extract_resource_refs_tolerates_malformed_json() -> None:
    refs = extract_resource_refs(
        path="/x",
        query=(),
        body=b"{not valid json",
        content_type="application/json",
    )
    assert refs == ()


def test_extract_resource_refs_is_sorted_and_deduplicated() -> None:
    refs = extract_resource_refs(
        path="/a/1/b/1",
        query=(),
        body=None,
        content_type=None,
    )
    assert list(refs) == sorted(set(refs))
