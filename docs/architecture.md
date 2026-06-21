# Charon Architecture (v1)

Charon is an authorization analysis tool. Its core is a **deterministic engine**. An optional, advisory **LLM layer** adds semantic understanding and human-readable explanations but is never required for correctness.

## Core architectural invariants

These are non-negotiable rules every module must uphold.

1. **Evidence-backed findings.** Every finding references one or more concrete, reproducible evidence artifacts (captured request/response, replayed request/response, a diff, or a policy contradiction). A finding with no evidence reference is invalid and must be rejected by the type system, not by convention.
2. **Determinism of the core.** Given the same inputs (captured traffic + config + seed), the deterministic engine produces byte-identical evidence and the same set of findings. No randomness, wall-clock, or network nondeterminism leaks into a finding's identity.
3. **LLM is advisory and optional.** LLM output may *annotate* (ownership inference, semantic labels, summaries, explanations) but may never *create*, *promote*, or *suppress* a finding. The finding set is computed before any LLM is consulted.
4. **Evidence beats inference.** When an LLM annotation conflicts with replay evidence, the evidence value is authoritative and the conflict is recorded. The LLM's claim is retained only as a labeled, lower-trust annotation.
5. **Provenance is mandatory.** Every field in a finding and every annotation carries a `source` tag: `Observed`, `Replayed`, `Derived` (deterministic computation), or `Inferred` (LLM). Reports must be able to render with all `Inferred` content stripped.
6. **Graceful degradation.** Disabling the LLM removes only semantic labels and prose quality. Capture, replay, comparison, evidence generation, finding detection, and reporting all still run to completion.
7. **The `enrich` layer is read-only.** The `enrich` layer must never create, modify, suppress, upgrade, downgrade, or delete findings. It may only attach annotations or explanations *by reference*. The finding set is sealed before enrichment runs and is immutable thereafter.

## V1 Non-Goals

The following are **intentionally out of scope for v1**. They are future-vision items only and must not influence v1 design, module boundaries, or data model. Do not add hooks, abstractions, or partial support for them in v1.

- **GraphQL support** (GraphQL-specific capture, replay, or authorization analysis).
- **WebSockets** (and other non-request/response or streaming protocols).
- **Workflow / state-machine testing** (multi-step stateful flows, session choreography).
- **Persona engines** (automated identity/persona generation and management beyond simple replay identities).
- **Any other future-vision feature** not explicitly listed in `docs/v1-scope.md`.

V1 targets HTTP(S) request/response authorization analysis only.

## Module boundaries

The codebase splits into a **deterministic core** and an **advisory layer**, separated by a hard boundary. The advisory layer depends on the core; the core never imports the advisory layer.

### Deterministic core (no LLM, ever)

- `capture` — Ingests/records HTTP(S) traffic into immutable, content-addressed `CapturedExchange` records. Pure I/O at the edges, deterministic records out.
- `model` — Canonical data types and the type-level invariant that a `Finding` cannot be constructed without an `Evidence` reference. See `docs/data-model.md`.
- `replay` — Re-issues requests under varied identities/contexts. Produces `ReplayResult`s. Target nondeterminism is captured and flagged, not hidden.
- `compare` — Normalizes and diffs responses (status, headers, body, access decision). Emits structured `Comparison` artifacts.
- `detect` — Authorization rule engine. The sole authority that creates `Finding`s.
- `evidence` — Assembles the evidence chain for each finding and computes stable content-addressed IDs.
- `report` — Renders findings + evidence. Has a mode switch to include or exclude all `Inferred` content.

### Advisory layer (optional, LLM-backed)

- `llm` — Thin client abstraction over the model provider. Returns fallible results; never panics the pipeline.
- `enrich` — Takes a *completed, sealed* finding/evidence set and attaches `Annotation`s. Read-only with respect to the finding set (invariant 7).

### Orchestration

- `pipeline` — Wires the stages. Enforces ordering: detection completes and findings are sealed *before* enrichment runs. Owns the LLM-availability decision.

## Data flow between modules

The pipeline is a one-directional flow. The finding set is *sealed* at the detect/evidence stage, then optionally enriched.

```
 [ capture ] --> CapturedExchange (immutable, content-addressed)
       |
       v
 [ replay ] -----> ReplayResult
       |
       v
 [ compare ] ----> Comparison
       |
       v
 [ detect ] -----> Finding (deterministic) --- requires --> Evidence
       |                                                       ^
       v                                                       |
 [ evidence ] --- assembles & content-addresses --------------/
       |
   == FINDINGS SEALED HERE (deterministic result is complete) ==
       |
       +----> [ report: deterministic mode ]  (fully usable, no LLM)
       |
       v   (optional, advisory)
 [ enrich (llm) ] --> Annotation (attached by reference, never mutates findings)
       |
       v
   [ report: enriched mode ]  (deterministic findings + advisory labels)
```

Data only flows *into* `enrich`; nothing flows *back* from `enrich` into `detect`/`evidence`.

## Deterministic vs. optionally-LLM modules

| Module | Determinism | Uses LLM |
|---|---|---|
| `capture`, `model`, `replay`, `compare`, `detect`, `evidence` | Deterministic | Never |
| `report` (deterministic mode) | Deterministic | Never |
| `pipeline` | Deterministic control flow; branches on LLM availability | No (only decides) |
| `llm`, `enrich` | Best-effort | Yes |
| `report` (enriched mode) | Deterministic skeleton + advisory overlay | Reads LLM output indirectly |

## Module acceptance criteria

Each module is considered correct for v1 only if it meets these criteria.

### `capture`
- Produces immutable, content-addressed `CapturedExchange` records.
- Same input traffic yields identical records and identical content addresses.
- Runs with no LLM present.

### `model`
- A `Finding` cannot be constructed without at least one `Evidence` reference (enforced at the type level).
- Every field and annotation carries a `Provenance` source tag.

### `replay`
- Re-issues requests deterministically given the same target behavior.
- Captures and flags target-side nondeterminism rather than hiding it.
- Runs with no LLM present.

### `compare`
- Produces structured `Comparison` artifacts from response pairs.
- Same inputs yield identical comparisons.
- Runs with no LLM present.

### `detect`
- **Produces findings without any LLM available.**
- Every emitted `Finding` references concrete `Evidence`.
- Same inputs yield the same finding set with stable IDs.
- Is the sole authority permitted to create findings.

### `evidence`
- Assembles a complete, walkable evidence chain for every finding.
- Computes stable, content-addressed evidence IDs that reproduce on re-run.

### `report`
- **Renders a complete deterministic report with all inferred annotations disabled.**
- Deterministic-mode output never contains LLM-sourced content.
- Enriched mode overlays advisory annotations without altering deterministic content.

### `llm`
- All calls are fallible and isolated; a failure never aborts the pipeline.
- Never invoked before findings are sealed.

### `enrich`
- **Optional and never required for successful execution.**
- Read-only: never creates, modifies, suppresses, upgrades, downgrades, or deletes findings.
- Attaches annotations by reference only; partial or failed enrichment leaves the finding set intact.

### `pipeline`
- Seals the finding set before any enrichment runs.
- Completes successfully whether or not the LLM is available.

## Failure modes when the LLM is unavailable

The pipeline treats LLM unavailability as a normal, expected state, not an error.

- **LLM disabled by config:** `enrich` is skipped. Report renders in deterministic mode. Exit status: success.
- **LLM times out / errors / rate-limited:** Each enrichment call is independently fallible. A failed call yields *no annotation* for that item. Other annotations still attach. The finding set is untouched.
- **Partial enrichment:** Reports render with whatever annotations succeeded; missing labels fall back to deterministic identifiers (e.g. raw endpoint path instead of a semantic name).
- **LLM returns malformed/unparseable output:** Discarded as if the call failed. Logged, never surfaced as a finding or as fact.
- **LLM contradicts evidence:** Evidence wins. The contradiction is recorded as a low-trust annotation and optionally flagged in the report's advisory-disagreements section.

The single guarantee: **the deterministic report is always producible.** Degradation is limited to label quality and explanation prose.

## Traceability: finding -> concrete evidence

Every `Finding` carries a verifiable chain back to raw observation:

- `Finding` holds one or more `evidence_ids` (content-addressed hashes), never inline prose-as-proof.
- Each `Evidence` references the concrete artifacts that produced it: the `CapturedExchange` id(s), the `ReplayRequest`/`ReplayResult` pair(s), and the `Comparison` that triggered the rule.
- Each `ReplayResult` references the exact request it was derived from and the captured baseline it was compared against.
- Content-addressing means any artifact can be independently re-verified: re-run the deterministic engine on the same capture and the same ids must reappear.
- Every field carries `Provenance`, so a reader can mechanically separate proven observation from LLM suggestion.

Audit path: `Finding -> Evidence -> Comparison -> (ReplayRequest, ReplayResult) -> CapturedExchange`. No link in that chain may be LLM-generated.

## Canonical documentation

The following files are the locked, canonical architecture references for v1:

- `docs/architecture.md` (this file)
- `docs/v1-scope.md`
- `docs/data-model.md`
