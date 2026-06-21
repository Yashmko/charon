Charon — semantic IDOR & authorization hunter

stop guessing IDs. start reasoning about ownership.
>Charon is evidence-driven: LLMs assist with semantic inference and explanation, but every security finding is backed by deterministic replay and observable behavior.

> Charon reverse-engineers an application's authorization model, continuously verifies it against reality, and detects semantic access-control violations that traditional IDOR scanners miss.

![status](https://img.shields.io/badge/status-design%20phase-orange)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> Working name. Swap it for whatever you like before you publish — check GitHub/PyPI for collisions first.

---

## Table of contents

- [The problem](#the-problem)
- [Related tools](#related-tools)
- [How it works](#how-it-works)
- [Stage breakdown](#stage-breakdown)
- [Authorization DNA & drift detection](#authorization-dna--drift-detection)
- [Data model](#data-model)
- [Planned CLI](#planned-cli)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Build roadmap](#build-roadmap)
- [OWASP mapping](#owasp-mapping)
- [Future vision (v2)](#future-vision-v2)
- [Scope & ethics](#scope--ethics)
- [Status](#status)

---

## The problem

Most IDOR/BOLA scanners work the same dumb way: take a request like `GET /api/orders/123`, swap the ID to `122`, `124`, or another user's value, and check if the response changes. This is brute force with no understanding of *what* the endpoint does or *who* should own the resource. It generates noise, misses authorization logic that depends on roles or relationships (a manager can see subordinates' data but not other managers'), and can't tell a correctly-redacted response from a real leak.

Charon replaces guessing with reasoning. It builds a model of resource ownership from the API spec and real traffic, generates authorization hypotheses ("user B should never see user A's invoice"), and only flags a finding when a response actually violates one.

---

## Related tools

Burp extensions like **Autorize** and **AuthMatrix** already do cross-account request replay and response diffing — that mechanism isn't new, and it's worth knowing that going in. What they don't do is reason: they tell you a response *changed*, not whether the change is actually a leak, and the ownership/role rules have to be configured by hand before the tool can use them. Charon's differentiation sits one layer up — inferring the ownership and policy model from traffic instead of hand-configuring it, and triaging findings semantically instead of by status code alone.

---

## How it works

```
┌─────────────────────┐
│   Input capture      │   API spec + multi-account traffic
└──────────┬───────────┘
           │
┌──────────▼───────────┐
│ Ownership modeling    │   LLM maps fields → resource owners
└──────────┬───────────┘
           │
┌──────────▼───────────┐
│ Hypothesis + test gen │   Crafts cross-account test cases
└──────────┬───────────┘
           │
┌──────────▼───────────┐
│ Live replay execution │   Fires requests with swapped tokens
└──────────┬───────────┘
           │
┌──────────▼───────────┐
│ Semantic triage+report│   Maps findings to OWASP API Top 10
└───────────────────────┘
```

Five stages, each consuming the previous stage's output. Every stage is independently testable — you can run ownership modeling against a saved capture without hitting a live target, which matters for CI and for safely iterating on the heuristics.

---

## Stage breakdown

### 1. Input capture

**Purpose:** collect ground truth about how the API behaves for at least two distinct accounts, so later stages have real traffic to reason over instead of guessing from the spec alone.

**Inputs:** an OpenAPI/Swagger spec (or Postman collection if no formal spec exists), plus a proxy capture (Burp/ZAP/mitmproxy) for each test account while it's used normally — log in, browse, create/read/update a few resources.

**What gets recorded, per transaction:**

| Field | Description |
|---|---|
| `account_label` | which test account made the request (e.g. `userA`, `userB`, `admin`) |
| `method` | HTTP verb |
| `raw_path` | the literal path as captured, e.g. `/api/orders/8821` |
| `path_template` | normalized route, e.g. `/api/orders/{id}` — lets the tool group requests to "the same endpoint" across accounts and across different IDs |
| `query_params` | parsed key/value pairs |
| `headers` | full header set; the auth header/cookie is kept (needed for replay later), everything else kept for context |
| `body` | parsed JSON/form body if present |
| `response.status` | HTTP status code |
| `response.headers` | response headers |
| `response.body` | parsed response body |
| `latency_ms` | response time — occasionally useful later for spotting timing-based auth check differences |

**Resource reference extraction:** for every transaction, the capture layer scans path segments, query params, and body fields for anything that looks like an identifier — UUID, numeric ID, slug — and records it as a `resource_ref`: which field it came from, its literal value, and which account's session it appeared in. Because `userA`'s session naturally references `userA`'s own resources, this is the raw signal the next stage needs: "this ID belongs to this account, under this endpoint template."

**Why two-plus accounts matter:** a single account's traffic only shows what *that* user is allowed to see. Cross-account capture is what makes "does B's token expose A's resource" a testable, concrete question instead of a guess.

### 2. Ownership modeling

**Purpose:** turn raw captured traffic into a resource ownership graph — for each endpoint template, what resource type it touches, which field is the owning identifier, and what scope (owner-only, role-gated, public) it's expected to have.

**Process:** an LLM reads the OpenAPI spec descriptions, the path template, and the response field names/structure (fed from stage 1), and reasons about ownership semantics. A field named `user_id` or `owner_id` in a response, or a path like `/users/{id}/invoices`, is a strong signal. The model also looks at REST conventions — a `DELETE` on `/admin/*` implies role-gating even without an explicit spec annotation.

**Output:** a graph where each node is a resource type (`order`, `invoice`, `profile`) with edges to the endpoints that touch it and the inferred ownership rule for each — plus a plain-English policy statement per role, e.g. "guests can only access public resources," "support can read but not edit," "admins bypass tenant restrictions." Surfacing the inferred policy in readable form, not just as an internal graph, is what lets stage 5 flag *contradictions* between stated policy and observed behavior instead of just isolated bad responses.

### 3. Hypothesis + test generation

**Purpose:** convert the ownership graph into concrete, falsifiable claims, then turn each claim into an actual request.

**Example hypothesis:** "a request to `/invoices/{id}` authenticated as `userB` should be rejected (403/404) when `{id}` belongs to `userA`."

**Test generation:** for every hypothesis, build a request template that takes a real captured request and swaps the auth context (token/cookie) while keeping the original resource ID — this produces the actual cross-account test case. Covers BOLA (object-level — can B read/write A's specific resource), BFLA (function-level — can a non-admin account hit an admin-only operation at all), and property-level cases — instead of only testing full-object GET swaps, also generate a single-field PATCH/PUT against another account's resource, since partial-write access is a common gap that read-only tests miss entirely.

### 4. Live replay execution

**Purpose:** actually fire the generated test cases against the live target.

**Process:** a thin replay engine takes each test case, swaps the `Authorization` header or session cookie to the other account's credentials, sends the request, and records the response alongside the original (same-account) response for comparison. Session/token refresh is handled per account so long test runs don't fail on expired auth.

### 5. Semantic triage + report

**Purpose:** separate real findings from noise. Not every non-403 response is a vulnerability — some endpoints correctly return empty or redacted data for the wrong account.

**Process:** the response body is checked against the ownership graph from stage 2. A finding is only raised when the response actually contains fields that semantically belong to the *other* account — name, email, address, balance, anything tagged as owner-scoped — not just because the status code wasn't a 403. Each finding gets a confidence score and a one-line explanation.

**Blast radius:** once a finding is confirmed, Charon queries the ownership graph for siblings — other endpoints touching the same resource type or matching the same route template family — and automatically reruns the same cross-account test against them. One confirmed leak on `/invoices/{id}` triggers an automatic check of `/invoices/{id}/export`, `/invoices/{id}/attachments`, and anything else sharing that resource type, instead of relying on you to think to test them by hand.

**Root cause clustering:** in the report output, findings sharing the same underlying cause — e.g. every endpoint in `InvoiceController` missing the same ownership check — are grouped under one root cause instead of listed as separate alerts. A report saying "1 root cause, 4 affected endpoints" is something a developer actually fixes; "4 findings" is something that gets triaged into a backlog and forgotten.

**"Why wasn't this blocked?":** every finding's report includes a short before/after — what the inferred policy expected for that role, what was actually observed, and a likely cause. One honesty note worth keeping in mind while building this: Charon is black-box, it never sees the target's source code, so this is an inferred hypothesis, not a traced execution log — it can't literally see "the ownership-check middleware didn't run." What it can credibly do is compare policy against behavior and name the most likely gap, especially when blast radius shows the same gap repeating across a whole route family:

```
Expected (from inferred policy): guest -> invoice: forbidden
Observed: guest token -> GET /invoices/8821 -> 200, returned owner_id + email + amount
Likely cause: ownership check missing or misconfigured for this resource —
repeats across 4 sibling endpoints in the same route family, suggesting the
gap is in shared handler logic rather than one-off endpoint code.
```

Still genuinely actionable — "the gap is shared logic, here's the evidence" — without claiming visibility into server internals Charon never actually has.

**Evidence-grade output:** every finding ships with the original (same-account) request, the swapped-account request, a structured response diff, and a minimal reproduction — the smallest request that still triggers the leak. The reasoning itself is stored as an explicit chain (resource owner, requester identity, what leaked, what the inferred policy predicted) rather than a single confidence sentence, so a reviewer can verify it step by step instead of just trusting a number.

**Output:** structured findings mapped to OWASP API Security Top 10 — primarily **API1:2023 Broken Object Level Authorization** and **API5:2023 Broken Function Level Authorization** — ready to drop into a pentest report.

---

## Authorization DNA & drift detection

Stage 2 already builds a policy model internally. Serializing it gives you something useful beyond a single run: a readable snapshot of the app's inferred authorization rules, and a diff between two snapshots over time.

```yaml
resource: invoice
owner: customer_id

permissions:
  owner: [read, download]
  accountant: [read, update]
  admin: ["*"]

forbidden:
  guest: ["*"]
```

Run Charon again after a refactor or redeploy and diff the new snapshot against the last one:

```diff
- guest -> read invoice ❌
+ guest -> read invoice ✅
```

This is one mechanism, not three features — snapshot the policy graph, store it, diff the next one against it. That single diff engine covers a human-readable authorization spec for the app, drift detection when a refactor silently widens access, and (with the CI wiring noted in future vision) regression checks tied to a specific deploy.

---

## Data model

Captured traffic and findings are stored in SQLite (no need for anything heavier at this scale).

```sql
CREATE TABLE captured_requests (
    id            INTEGER PRIMARY KEY,
    account_label TEXT NOT NULL,
    method        TEXT NOT NULL,
    raw_path      TEXT NOT NULL,
    path_template TEXT NOT NULL,
    query_params  TEXT,   -- JSON
    headers       TEXT,   -- JSON
    body          TEXT,   -- JSON or raw text
    captured_at   TIMESTAMP
);

CREATE TABLE captured_responses (
    id           INTEGER PRIMARY KEY,
    request_id   INTEGER REFERENCES captured_requests(id),
    status_code  INTEGER,
    headers      TEXT,   -- JSON
    body         TEXT,   -- JSON or raw text
    latency_ms   INTEGER
);

CREATE TABLE resource_refs (
    id             INTEGER PRIMARY KEY,
    request_id     INTEGER REFERENCES captured_requests(id),
    field_location TEXT,  -- 'path' | 'query' | 'body'
    field_name     TEXT,
    value          TEXT,
    inferred_type  TEXT   -- 'uuid' | 'int' | 'slug'
);

CREATE TABLE ownership_graph (
    id              INTEGER PRIMARY KEY,
    resource_type   TEXT NOT NULL,
    path_template   TEXT NOT NULL,
    owner_field     TEXT,
    scope           TEXT  -- 'owner_only' | 'role_gated' | 'public'
);

CREATE TABLE findings (
    id                   INTEGER PRIMARY KEY,
    hypothesis           TEXT NOT NULL,
    original_request_id  INTEGER REFERENCES captured_requests(id),  -- same-account baseline
    swapped_request_id   INTEGER REFERENCES captured_requests(id),  -- cross-account replay
    leaked_fields        TEXT,   -- JSON list
    response_diff        TEXT,   -- JSON: field-level diff between baseline and swapped response
    confidence           REAL,
    owasp_class          TEXT,   -- 'API1' | 'API5' | ...
    explanation           TEXT,
    repro_steps           TEXT,   -- minimal reproduction
    sibling_of             INTEGER REFERENCES findings(id)  -- set when surfaced via blast radius
);
```

Example captured transaction, as it would be stored:

```json
{
  "account_label": "userB",
  "method": "GET",
  "raw_path": "/api/invoices/8821",
  "path_template": "/api/invoices/{id}",
  "headers": { "Authorization": "Bearer <userB_token>" },
  "response": {
    "status_code": 200,
    "body": { "id": 8821, "owner_id": "userA", "amount": 4200, "email": "usera@example.com" }
  },
  "resource_refs": [
    { "field_location": "path", "field_name": "id", "value": "8821", "inferred_type": "int" }
  ]
}
```

This single record — userB's token, userA's invoice ID, response containing userA's email — is exactly the shape a finding gets built from.

Example evidence-grade finding, as it would appear in a report:

```json
{
  "hypothesis": "userB should not be able to read userA's invoice",
  "owasp_class": "API1",
  "confidence": 0.93,
  "leaked_fields": ["email", "amount", "owner_id"],
  "explanation": "userB's token returned userA's invoice including PII fields tagged owner-scoped in the ownership graph",
  "evidence": {
    "baseline_request": "GET /api/invoices/8821 (as userA) -> 200",
    "swapped_request": "GET /api/invoices/8821 (as userB) -> 200",
    "response_diff": "swapped response identical to baseline; no redaction applied"
  },
  "repro_steps": "Authenticate as userB, GET /api/invoices/8821 (an ID owned by userA)",
  "sibling_of": null
}
```

---

## Planned CLI

Target interface (not yet implemented — this is the design target):

```bash
# Step 1: capture traffic for each account through a local proxy
charon capture --account userA --proxy :8080
charon capture --account userB --proxy :8080
charon capture --account admin --proxy :8080

# Step 2: build the ownership graph from spec + captures
charon model --spec openapi.json --captures ./captures.db

# Step 3: generate hypotheses + test cases
charon generate --captures ./captures.db --out ./testcases.json

# Step 4: replay against the live target
charon run --testcases ./testcases.json --target https://staging.example.com

# Step 5: triage + report
charon report --format markdown --out ./findings.md
```

---

## Tech stack

- **Language:** Python 3.11+ (fastest path to an LLM-calling, HTTP-replaying CLI tool)
- **HTTP replay:** `httpx`
- **Storage:** SQLite (no infra overhead, portable single-file DB)
- **LLM calls:** Groq API for the ownership-modeling and triage classification steps — these are many small, low-latency calls rather than one big generation, which is exactly what Groq's inference speed is good for
- **Spec parsing:** `openapi-spec-validator` / `prance` for OpenAPI ingestion
- **Runs on:** GitHub Codespaces or any cloud shell — nothing here needs local compute, so it's fine on low-RAM hardware

---

## Project structure

```
charon/
├── capture/          # proxy listener, traffic recorder
├── modeling/         # ownership graph builder (LLM calls)
├── generate/         # hypothesis + test case generation
├── replay/           # live request execution engine
├── triage/           # semantic response classification + scoring
├── report/           # OWASP-mapped markdown/JSON report output
├── db/                # SQLite schema + migrations
├── cli.py            # entrypoint
└── tests/
```

---

## Build roadmap

Scoped to get something demoable fast, then deepen it.

**Week 1 — capture + replay skeleton**
Proxy-based capture for one account, SQLite storage, manual cross-account replay (hardcode the token swap). No AI yet. Goal: prove you can record a request as userA and successfully replay it as userB against a real (authorized) target.

**Week 2 — ownership modeling**
Feed captures + OpenAPI spec into an LLM call, produce the ownership graph. Validate it by hand against a few endpoints you already know the answer for (you've got this from Tirth.com).

**Week 3 — hypothesis generation + automated replay**
Turn the graph into test cases automatically, wire up the replay engine to run all of them in one pass.

**Week 4 — semantic triage + reporting**
Add the response-classification step so findings are scored instead of dumped raw, generate the OWASP-mapped report output.

Each week ends with something that runs end-to-end, even if rough — that's what makes this demoable at any point instead of an unfinished pile.

---

## OWASP mapping

| Finding type | OWASP API Security Top 10 (2023) |
|---|---|
| Object-level access bypass (IDOR) | API1 — Broken Object Level Authorization |
| Function-level access bypass | API5 — Broken Function Level Authorization |
| Excessive data exposure in response | API3 — Broken Object Property Level Authorization |

---

## Future vision (v2)

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

---

## Scope & ethics

This tool fires authenticated requests across account boundaries — it is an active testing tool, not a passive scanner. Run it only against systems you have explicit written authorization to test. Do not point it at production systems without a defined testing window and rollback plan, since cross-account writes (if you extend it beyond GET requests) can modify real data.

---

## Status

Design phase. Architecture and data model above are finalized; implementation follows the build roadmap. This README will be updated as each stage ships.