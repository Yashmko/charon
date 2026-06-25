# Charon

Charon is a deterministic, evidence-driven authorization analysis project for
HTTP(S) request/response APIs.

The core product is a deterministic engine. Optional LLM-backed enrichment may
add semantic labels and human-readable explanations, but it must never create,
promote, suppress, or alter findings. Evidence and reproducibility are the trust
boundary.

## Canonical Architecture

The locked v1 references are:

- `docs/architecture.md`
- `docs/v1-scope.md`
- `docs/data-model.md`

If this README and the documents above appear to disagree, the documents above
are authoritative.

## Current Status

The repository currently implements the model layer only:

- immutable, content-addressed core artifacts;
- provenance tagging for observed, replayed, derived, and inferred values;
- evidence-backed `Finding` construction;
- advisory `Annotation` objects attached by reference;
- tests for model determinism, provenance, traceability, and immutability.

The operational pipeline is not implemented yet. There is no capture engine,
network replay engine, response comparison engine, detector, evidence assembler,
report renderer, LLM client, enrichment stage, database layer, or CLI.

## V1 Pipeline Target

The planned deterministic flow is:

```text
capture -> replay -> compare -> detect -> evidence -> report
```

Optional enrichment runs only after deterministic findings are sealed:

```text
sealed findings/evidence -> enrich -> enriched report overlay
```

Data never flows from enrichment back into detection or evidence assembly.

## Related Tools

Burp extensions like **Autorize** and **AuthMatrix** already do cross-account
request replay and response diffing. Charon's differentiation sits one layer up:
inferring the ownership and policy model from traffic instead of
hand-configuring it, and triaging findings semantically instead of by status
code alone.

## Implemented Package Layout

```text
charon/
|-- __init__.py
`-- model/
    |-- __init__.py
    |-- addressing.py
    |-- annotation.py
    |-- comparison.py
    |-- evidence.py
    |-- exceptions.py
    |-- exchange.py
    |-- finding.py
    |-- provenance.py
    `-- replay.py
```

## Implementation Matrix

| Module | Planned | Implemented | Tested | Status |
|---|---:|---:|---:|---|
| `model.addressing` | Yes | Yes | Yes | Implemented |
| `model.provenance` | Yes | Yes | Yes | Implemented |
| `model.exchange` | Yes | Yes | Yes | Model artifact only |
| `model.replay` | Yes | Yes | Yes | Model artifacts only |
| `model.comparison` | Yes | Yes | Yes | Model artifacts only |
| `model.evidence` | Yes | Yes | Yes | Model artifact only |
| `model.finding` | Yes | Yes | Yes | Implemented |
| `model.annotation` | Yes | Yes | Yes | Implemented |
| `capture` | Yes | No | No | Missing |
| `replay` engine | Yes | No | No | Missing |
| `compare` engine | Yes | No | No | Missing |
| `detect` | Yes | No | No | Missing |
| `evidence` assembly | Yes | No | No | Missing |
| `report` | Yes | No | No | Missing |
| `llm` | Yes | No | No | Missing |
| `enrich` | Yes | No | No | Missing |
| `pipeline` | Yes | No | No | Missing |
| `cli` | Not canonical v1 module | No | No | Not started |

## Development

Install development tools:

```bash
python -m pip install -e ".[dev]"
```

Run the required checks:

```bash
pytest
ruff check .
mypy .
```

## Scope And Ethics

Charon is intended for authorized security testing only. The future replay
engine will issue authenticated requests across identity boundaries, so it must
be used only against systems where the tester has explicit permission and an
approved testing window.

## Next Implementation Task

The highest-value next implementation task is the deterministic `compare`
module. It should consume existing `CapturedExchange` and `ReplayResult`
artifacts, normalize response status/headers/body deterministically, classify
access decisions without LLM input, and emit stable `Comparison` artifacts.

## OWASP Mapping

| Finding type | OWASP API Security Top 10 (2023) |
|---|---|
| Object-level access bypass (IDOR) | API1 — Broken Object Level Authorization |
| Function-level access bypass | API5 — Broken Function Level Authorization |
| Excessive data exposure in response | API3 — Broken Object Property Level Authorization |

## Future Vision

The v1 scope above — input capture, ownership modeling with policy inference, hypothesis/test generation including property-level cases, replay, semantic triage with blast radius — is intentionally finishable in about a month. The ideas below are explicitly **out of scope for v1**, noted here so the ambition is documented without turning the first build into an unfinishable sprawl.

**Deeper authorization surface**
- Workflow/state-machine testing — model multi-step flows (invite → accept → upgrade → cancel) and generate transition-abuse test cases
- Temporal authorization — check whether access is actually revoked after role downgrade, org removal, or session invalidation, not just at a single point in time

**Identity & relationship modeling**
- Full identity graph beyond simple ownership: user → team → org → project, delegated access, inherited permissions — answering questions like "can someone outside Team Red reach Repo X"

**Multi-protocol coverage**
- GraphQL schema-aware ownership inference (nested object edges, node-level auth)
- File/object storage checks — signed URLs, S3/Firebase buckets, CDN assets, export endpoints
- Cross-service identity correlation across REST, GraphQL, WebSockets, and background jobs

**Attack narrative layer**
- Privilege escalation chain explorer — chain isolated findings into a full attack path (this is the exploit-chain-synthesizer idea from earlier in scoping this project; it fits naturally once the ownership graph and findings store already exist)
- Persona engine — auto-provision synthetic accounts (suspended, unverified, expired-subscription, external collaborator) and replay the full test suite as each one
- Business-impact risk scoring — express a finding as estimated blast radius across tenants/accounts, not just a severity label

**Tooling integrations**
- Burp Suite extension so live captured traffic flows straight into Charon
- CI-wired regression — hook the authorization-DNA diff (now in v1) into CI so it runs on every deploy and ties any drift to the commit that caused it, instead of running it manually
- Org-defined policy DSL — let a tester declare custom rules ("billing objects should never expose PII across accounts") and validate the app against them directly, turning Charon from a detector into a verifier

Each of these is a legitimate multi-week-to-multi-month effort on its own. Pick one as a v2 milestone once v1 is shipped and demoable — don't start more than one at a time.
