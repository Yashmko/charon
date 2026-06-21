# Charon Data Model (v1)

Canonical data types for the deterministic core and advisory layer. This is a locked reference alongside `docs/architecture.md` and `docs/v1-scope.md`. It describes contracts and invariants, not implementation.

## Provenance

Every field in a finding and every annotation carries a provenance source tag:

- `Observed` — captured directly from real traffic.
- `Replayed` — produced by a replayed request issued by Charon.
- `Derived` — produced by deterministic computation over observed/replayed data.
- `Inferred` — produced by the LLM. Advisory only; never proof.

Reports must be able to render with all `Inferred` content stripped.

## Core types (deterministic)

### CapturedExchange
- Immutable record of one request/response pair plus metadata.
- Content-addressed by a stable hash of its canonicalized content.
- Provenance: `Observed`.

### ReplayRequest
- A request Charon issues, derived from a `CapturedExchange` under a varied identity/context.
- References the originating `CapturedExchange` id.

### ReplayResult
- The response to a `ReplayRequest`.
- References its `ReplayRequest` and the captured baseline it is compared against.
- Records any observed target-side nondeterminism.
- Provenance: `Replayed`.

### Comparison
- Structured diff of two responses (status, headers, body, access decision).
- References the inputs it compared.
- Provenance: `Derived`.

### Evidence
- Assembled, content-addressed proof artifact for a finding.
- References the concrete artifacts that produced it: `CapturedExchange` id(s), `ReplayRequest`/`ReplayResult` pair(s), and the triggering `Comparison`.
- Provenance: `Derived`.

### Finding
- A detected authorization issue produced solely by `detect`.
- **Invariant: cannot be constructed without at least one `Evidence` reference** (`evidence_ids`). Enforced at the type level.
- Holds no inline prose-as-proof; proof lives in referenced `Evidence`.
- Provenance of its core fields: `Observed` / `Replayed` / `Derived` only.

## Advisory types (optional, LLM-backed)

### Annotation
- Advisory metadata attached *by reference* to a sealed `Finding` or `Evidence` (e.g. semantic label, ownership inference, policy summary, explanation).
- Provenance: `Inferred`.
- **Invariant: an `Annotation` can never create, modify, suppress, upgrade, downgrade, or delete a `Finding`.** It only attaches to an existing one.
- May record a disagreement with evidence; when it does, evidence remains authoritative.

## Traceability

Every finding is auditable along a chain that ends at raw captured bytes and contains no LLM-generated link:

```
Finding -> Evidence -> Comparison -> (ReplayRequest, ReplayResult) -> CapturedExchange
```

Content-addressing guarantees that re-running the deterministic engine on the same capture reproduces the same ids.
