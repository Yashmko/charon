"""``ReplayRequest`` and ``ReplayResult``.

A :class:`ReplayRequest` is a request Charon issues, derived from a
:class:`~charon.model.exchange.CapturedExchange` under a varied identity, and
references that originating exchange by id. A :class:`ReplayResult` is the
response to a ``ReplayRequest``; it references its request and the captured
baseline it is compared against, records any target-side nondeterminism, and
has provenance ``Replayed``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from charon.model.addressing import ContentAddress, content_address
from charon.model.exchange import HttpMessage
from charon.model.provenance import Provenance

__all__ = ["ReplayIdentity", "ReplayRequest", "ReplayResult"]


@dataclass(frozen=True, slots=True)
class ReplayIdentity:
    """The identity/context a replay is issued under.

    This is a simple replay identity (a labelled credential context), not a
    persona engine: persona generation is explicitly out of scope for v1.
    The credential material itself is intentionally not stored on the model;
    only the stable label is recorded so artifacts remain reproducible.
    """

    label: str

    def to_canonical(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable view of this identity."""
        return {"label": self.label}


@dataclass(frozen=True, slots=True)
class ReplayRequest:
    """A request Charon issues, derived from a captured exchange.

    References the originating ``CapturedExchange`` by its content address.
    The request is content-addressed so the same derivation reproduces the
    same id.
    """

    source_exchange_id: ContentAddress
    identity: ReplayIdentity
    method: str
    url: str
    request: HttpMessage
    request_id: ContentAddress = field(default="", compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", self.method.upper())
        object.__setattr__(self, "request_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this request."""
        return {
            "type": "ReplayRequest",
            "source_exchange_id": self.source_exchange_id,
            "identity": self.identity.to_canonical(),
            "method": self.method,
            "url": self.url,
            "request": self.request.to_canonical(),
        }


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """The response to a :class:`ReplayRequest`.

    References its originating ``ReplayRequest`` and the captured baseline
    exchange it is to be compared against. Target-side nondeterminism is
    recorded explicitly (flagged, not hidden). Provenance is ``Replayed``.
    """

    replay_request_id: ContentAddress
    baseline_exchange_id: ContentAddress
    status_code: int
    response: HttpMessage
    #: Human/machine-readable notes describing observed target nondeterminism
    #: (e.g. a volatile timestamp field). Sorted for deterministic addressing.
    nondeterminism_notes: tuple[str, ...] = ()
    result_id: ContentAddress = field(default="", compare=False)

    provenance: Provenance = field(default=Provenance.REPLAYED, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "nondeterminism_notes", tuple(sorted(self.nondeterminism_notes))
        )
        object.__setattr__(self, "result_id", self._compute_id())

    def _compute_id(self) -> ContentAddress:
        return content_address(self.to_canonical())

    @property
    def has_observed_nondeterminism(self) -> bool:
        """Return ``True`` if target-side nondeterminism was recorded."""
        return bool(self.nondeterminism_notes)

    def to_canonical(self) -> dict[str, Any]:
        """Return the deterministic content used to address this result."""
        return {
            "type": "ReplayResult",
            "replay_request_id": self.replay_request_id,
            "baseline_exchange_id": self.baseline_exchange_id,
            "status_code": self.status_code,
            "response": self.response.to_canonical(),
            "nondeterminism_notes": list(self.nondeterminism_notes),
        }
