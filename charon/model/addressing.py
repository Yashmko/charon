"""Deterministic content-addressing for core artifacts.

Content addresses are stable SHA-256 hashes over a canonical JSON encoding of
an artifact's content. The encoding is deterministic: keys are sorted, there
is no wall-clock or randomness, and no network input is consulted. Re-running
the deterministic engine over the same inputs reproduces the same addresses
(architecture invariant 2 and the traceability guarantees).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["ContentAddress", "content_address", "canonical_json"]

#: Prefix used so a content address is self-describing and unambiguous.
_ADDRESS_PREFIX = "sha256:"

#: Type alias for the opaque, content-addressed identifier string.
ContentAddress = str


def canonical_json(payload: Any) -> str:
    """Serialize ``payload`` to a deterministic, canonical JSON string.

    The serialization sorts object keys and uses compact separators so that
    semantically-equal payloads always produce byte-identical output.

    :raises TypeError: if ``payload`` contains a value JSON cannot encode.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def content_address(payload: Any) -> ContentAddress:
    """Compute the deterministic content address of ``payload``.

    ``payload`` must be a JSON-serializable structure describing the
    *content* of an artifact (never including its own address, and never a
    wall-clock timestamp or other nondeterministic value).
    """
    encoded = canonical_json(payload).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return f"{_ADDRESS_PREFIX}{digest}"
