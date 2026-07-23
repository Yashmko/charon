# Charon

Deterministic, evidence-driven HTTP authorization analysis.

Charon ingests captured HTTP traffic, replays it under alternate identities,
compares responses, and produces evidence-backed findings for authorization
issues (BOLA/IDOR, BFLA, and others). The core is fully deterministic — same
inputs always produce identical evidence and findings. An optional advisory
LLM layer (not yet implemented) may add semantic labels but never creates or
suppresses findings.

## Implemented Modules

```
capture → replay → compare → detect → report
```

| Module | Status | Description |
|--------|--------|-------------|
| `model` | Complete | Immutable, content-addressed core artifacts with provenance tagging |
| `capture` | Complete | Traffic ingestion from HAR files and raw dicts with normalization |
| `replay` | Complete | HTTP replay engine with pluggable transports and credential management |
| `compare` | Complete | Deterministic response diffing with volatile-field suppression |
| `detect` | Complete | BOLA/IDOR and BFLA detection producing evidence-backed findings |
| `report` | Complete | Deterministic JSON and Markdown renderers with traceability |
| `pipeline` | Complete | Orchestration wiring all stages together |
| `cli` | Complete | Command-line interface (`charon analyze`) |

### Not yet implemented
- Advisory LLM layer (enrichment, annotation)
- Ownership/resource relationship inference
- Multi-identity matrix analysis
- Additional detection rules (BOPLA, privilege escalation, policy contradiction)
- Confidence scoring

See `docs/architecture.md`, `docs/v1-scope.md`, and `docs/data-model.md` for
the locked v1 design.

## Quick Start

```bash
pip install "charon[replay]"
```

Run analysis on a HAR capture with a replay credential:

```bash
charon analyze capture.har \
  --credentials creds.json \
  --format json \
  --output report.json
```

Credentials file format (`creds.json`):

```json
[
  {
    "label": "userB",
    "bearer_token": "eyJhbGciOiJIUzI1NiIs..."
  }
]
```

Output formats: `json`, `markdown`, `both`.

## Development

```bash
python -m pip install -e ".[dev]"
```

Run checks:

```bash
pytest
ruff check .
mypy .
```

### Supported credential types

- Bearer token (`bearer_token`)
- API key with configurable header name (`api_key`, `api_key_header`)
- Cookie-based auth (`cookies`)
- Arbitrary extra headers (`extra_headers`)

Inline credentials (for local/testing only — secrets may leak through shell
history):

```bash
charon analyze capture.har \
  --credential "userB=bearer:TOKEN" \
  --format json
```

## CLI

```
usage: charon analyze [-h] [--credentials FILE] [--credential SPEC]
                      [--output FILE] [--format {json,markdown,both}]
                      [--mode {deterministic,enriched}]
                      [--timeout SECONDS] [--verbose]
                      input
```

## OWASP Mapping

| Detection | OWASP API Security Top 10 (2023) |
|-----------|----------------------------------|
| BOLA/IDOR (cross-account object access) | API1 — Broken Object Level Authorization |
| BFLA (privilege escalation via function access) | API5 — Broken Function Level Authorization |

## Ethics

Charon is intended for authorized security testing only. The replay engine
issues authenticated requests across identity boundaries and must be used
only against systems where the tester has explicit permission.

## License

MIT
