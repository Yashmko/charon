# Charon V1 Scope

This document defines what is in and out of scope for Charon v1. It is a canonical, locked reference alongside `docs/architecture.md` and `docs/data-model.md`.

## In scope (v1)

- HTTP(S) request/response authorization analysis.
- Traffic capture into immutable, content-addressed records.
- Request replay under varied identities/contexts.
- Deterministic response comparison and diffing.
- Deterministic authorization finding detection (e.g. IDOR, missing authz, privilege escalation, policy contradiction).
- Evidence assembly with content-addressed, reproducible IDs.
- Deterministic reporting, with an enriched mode for optional advisory annotations.
- Optional LLM-backed enrichment: ownership inference, semantic labeling, policy summarization, human-readable explanations.

## V1 Non-Goals

The following are **intentionally out of scope for v1**. They are future-vision items only and must not influence v1 design, module boundaries, or data model. Do not add hooks, abstractions, or partial support for them in v1.

- **GraphQL support** (GraphQL-specific capture, replay, or authorization analysis).
- **WebSockets** (and other non-request/response or streaming protocols).
- **Workflow / state-machine testing** (multi-step stateful flows, session choreography).
- **Persona engines** (automated identity/persona generation and management beyond simple replay identities).
- **Any other future-vision feature** not explicitly listed in the in-scope section above.

## Guiding principle

The deterministic core is the product. The LLM is an optional enhancement. Anything that would make the LLM mandatory, or that would compromise determinism, evidence-backing, or traceability, is out of scope for v1 regardless of where it appears on this list.
