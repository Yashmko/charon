"""Deterministic ownership inference for Charon.

The ``ownership`` module analyzes captured exchanges to infer which accounts
own which resources, producing a deterministic
:class:`~charon.ownership.model.OwnershipMap`.

Design goals:

* Same exchanges and config yield identical ownership maps.
* Runs with no LLM present; nothing here is advisory.
* Inference is purely mechanical: it scans response-body JSON for
  configured owner-field patterns (e.g. ``owner_id``, ``userId``).
"""

from charon.ownership.config import OwnershipConfig
from charon.ownership.engine import OwnershipEngine
from charon.ownership.model import OwnershipInference, OwnershipMap

__all__ = [
    "OwnershipConfig",
    "OwnershipEngine",
    "OwnershipInference",
    "OwnershipMap",
]
