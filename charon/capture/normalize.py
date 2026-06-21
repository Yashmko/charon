"""Deterministic normalization helpers for captured HTTP data.

Every function here is a pure, deterministic transformation: no wall-clock,
no randomness, no network. Applying them to equivalent inputs always yields
byte-identical output, which is what makes a ``CapturedExchange`` content
address stable across runs and platforms (architecture invariant 2).
"""

from __future__ import annotations

import json
import re
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

__all__ = [
    "normalize_method",
    "normalize_url",
    "normalize_headers",
    "normalize_query",
    "extract_resource_refs",
]

#: Default ports stripped during URL canonicalization.
_DEFAULT_PORTS = {"http": "80", "https": "443"}

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_INT_RE = re.compile(r"^-?\d+$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")


def normalize_method(method: str) -> str:
    """Return ``method`` upper-cased and stripped of surrounding whitespace."""
    return method.strip().upper()


def normalize_query(query: str) -> tuple[tuple[str, str], ...]:
    """Parse a raw query string into sorted ``(key, value)`` pairs.

    Sorting makes query ordering irrelevant to the content address while
    preserving duplicate keys (kept as repeated pairs). Percent-decoding is
    applied so equivalent encodings collapse to the same parsed form.
    """
    pairs = parse_qsl(query, keep_blank_values=True)
    return tuple(sorted(pairs))


def normalize_url(url: str) -> str:
    """Canonicalize a URL deterministically.

    * Scheme and host are lower-cased.
    * Default ports (80/http, 443/https) are stripped.
    * The query is parsed and re-encoded with keys sorted.
    * Fragments are dropped (never sent to the server, so not part of the
      observed request identity).
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()

    netloc = hostname
    if parts.port is not None:
        port = str(parts.port)
        if _DEFAULT_PORTS.get(scheme) != port:
            netloc = f"{hostname}:{port}"
    # Preserve userinfo if present (rare in captures, but observed if there).
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo = f"{userinfo}:{parts.password}"
        netloc = f"{userinfo}@{netloc}"

    query = urlencode(normalize_query(parts.query))
    return urlunsplit((scheme, netloc, parts.path, query, ""))


def normalize_headers(
    headers: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    """Lower-case header names and return the set sorted for stability.

    HTTP header names are case-insensitive, so lower-casing plus sorting
    keeps the content address stable regardless of the casing or ordering a
    backend emitted. Header *values* are preserved verbatim. Duplicate
    headers are retained as repeated pairs.
    """
    lowered = tuple((name.lower(), value) for name, value in headers)
    return tuple(sorted(lowered))


def _classify_ref(value: str) -> str | None:
    """Classify ``value`` as a resource identifier type, or ``None``.

    Recognizes UUIDs, integers, and slugs. Returns the inferred type name
    (``"uuid"`` / ``"int"`` / ``"slug"``) or ``None`` if it does not look
    like an identifier.
    """
    if _UUID_RE.match(value):
        return "uuid"
    if _INT_RE.match(value):
        return "int"
    if _SLUG_RE.match(value):
        return "slug"
    return None


def _refs_from_json(
    payload: object, prefix: str
) -> list[tuple[str, str, str]]:
    """Recursively extract identifier-looking scalars from a JSON structure.

    Field location is reported as a dotted/indexed path under ``prefix``
    (e.g. ``"body.items[0].id"``) so refs are stable and human-traceable.
    """
    found: list[tuple[str, str, str]] = []
    if isinstance(payload, dict):
        for key in sorted(payload):
            found.extend(_refs_from_json(payload[key], f"{prefix}.{key}"))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            found.extend(_refs_from_json(item, f"{prefix}[{index}]"))
    elif isinstance(payload, str):
        inferred = _classify_ref(payload)
        if inferred is not None:
            # field name is the last path segment for readability.
            name = prefix.rsplit(".", 1)[-1]
            found.append((prefix, name, payload))
    elif isinstance(payload, bool):
        # bool is a subclass of int; never an identifier. Ignore explicitly.
        pass
    elif isinstance(payload, int):
        found.append((prefix, prefix.rsplit(".", 1)[-1], str(payload)))
    return found


def extract_resource_refs(
    *,
    path: str,
    query: tuple[tuple[str, str], ...],
    body: bytes | None,
    content_type: str | None,
) -> tuple[tuple[str, str, str], ...]:
    """Deterministically extract resource references from a request.

    Scans path segments, query parameters, and (when the body is JSON)
    body fields for identifier-looking values (UUID / int / slug) and
    returns them as sorted ``(location, name, value)`` triples matching the
    model's ``CapturedExchange.resource_refs`` shape.

    The scan is purely deterministic and never consults an LLM; semantic
    ownership inference is explicitly *not* done here.
    """
    refs: list[tuple[str, str, str]] = []

    # Path segments: location "path", name is the 1-based segment index.
    segments = [seg for seg in path.split("/") if seg]
    for index, segment in enumerate(segments, start=1):
        if _classify_ref(segment) is not None:
            refs.append(("path", f"segment{index}", segment))

    # Query params: location "query", name is the param key.
    for key, value in query:
        if _classify_ref(value) is not None:
            refs.append(("query", key, value))

    # JSON body fields: location is the dotted path under "body".
    if body is not None and content_type and "json" in content_type.lower():
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if parsed is not None:
            refs.extend(_refs_from_json(parsed, "body"))

    return tuple(sorted(set(refs)))
