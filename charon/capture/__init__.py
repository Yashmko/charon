"""Deterministic HTTP(S) traffic capture for Charon's core.

The ``capture`` module ingests HTTP exchanges from one of several pluggable
backends (HAR files, raw dictionaries, and -- in future -- Burp/mitmproxy
exports), normalizes them deterministically, and converts them into the
immutable, content-addressed :class:`~charon.model.CapturedExchange` records
defined by the model layer.

Design goals (see ``docs/architecture.md`` -> ``capture`` acceptance
criteria):

* Same input traffic yields identical records and identical content
  addresses.
* Runs with no LLM present; nothing here is advisory.
* Backends are interchangeable: every backend yields a backend-agnostic
  :class:`RawExchange`, and a single normalization/conversion path turns
  that into a ``CapturedExchange``. Downstream code never sees backend
  specifics.
* Runtime configuration and secrets (``CaptureConfig``) are kept separate
  from the persisted deterministic artifact.

This module deliberately contains no replay, compare, detect, evidence,
report, or enrichment logic.
"""

from charon.capture.backends import (
    CaptureBackend,
    HarCaptureBackend,
    RawDictCaptureBackend,
)
from charon.capture.config import CaptureConfig, HeaderAction
from charon.capture.errors import CaptureError, MalformedExchangeError
from charon.capture.normalize import (
    extract_resource_refs,
    normalize_headers,
    normalize_method,
    normalize_query,
    normalize_url,
)
from charon.capture.recorder import CaptureRecorder
from charon.capture.raw import RawExchange, RawMessage

__all__ = [
    "CaptureBackend",
    "CaptureConfig",
    "CaptureError",
    "CaptureRecorder",
    "HarCaptureBackend",
    "HeaderAction",
    "MalformedExchangeError",
    "RawDictCaptureBackend",
    "RawExchange",
    "RawMessage",
    "extract_resource_refs",
    "normalize_headers",
    "normalize_method",
    "normalize_query",
    "normalize_url",
]
