"""Deterministic response comparison for Charon's core.

The ``compare`` module normalizes and diffs a baseline
:class:`~charon.model.CapturedExchange` against a successful
:class:`~charon.model.ReplayResult`, emitting a structured, content-addressed
:class:`~charon.model.Comparison`.

Design goals (see ``docs/architecture.md`` -> ``compare`` acceptance
criteria):

* Produces structured ``Comparison`` artifacts from response pairs.
* Same inputs yield identical comparisons (stable content address).
* Runs with no LLM present; nothing here is advisory or semantic.

The module classifies an :class:`~charon.model.AccessDecision` purely and
mechanically from the HTTP status code. It never infers vulnerabilities,
ownership, authorization policy, severity, or findings -- those belong to
later modules. It also never mutates capture or replay artifacts.
"""

from charon.compare.config import ComparisonConfig
from charon.compare.engine import ComparisonEngine, classify_access_decision

__all__ = [
    "ComparisonConfig",
    "ComparisonEngine",
    "classify_access_decision",
]
