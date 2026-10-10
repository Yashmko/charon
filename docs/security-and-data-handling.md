# Security and Data Handling

Charon replays HTTP requests across configured identity contexts. Treat both its
inputs and outputs as security-sensitive test artifacts.

## Before running a scan

- Obtain explicit written authorization for every target and identity you use.
- Define hosts, paths, accounts, test window, rate limits, and stop conditions.
- Use dedicated test accounts and synthetic or non-sensitive records whenever
  possible. Do not use production credentials unless the owner explicitly
  authorizes that approach.
- Start with a small capture and a low-impact endpoint. Replaying a captured
  request can trigger server-side effects; Charon is not a read-only guarantee.

## Capture files and reports

The default `CaptureRecorder` policy redacts configured sensitive **header
values** (for example `Authorization`, `Cookie`, and `Set-Cookie`) before
addressing an artifact. It does not currently scrub request/response bodies,
URL query values, or sensitive values in arbitrary non-configured headers.
Bodies are retained as raw bytes to preserve evidence fidelity.

Therefore:

- Review and sanitize HAR/JSON captures before committing, sharing, or uploading
  them. Captures may contain credentials, session identifiers, personal data,
  API keys, and full request/response bodies.
- Keep credential files and reports outside version control. Use least-privilege
  credentials and rotate any secret that was accidentally exposed.
- Do not use `HeaderAction.KEEP` on real credentials unless there is a specific,
  approved need to retain them.
- Remember that redaction is not data anonymization. URLs, identifiers,
  response bodies, and report field-difference values may still be sensitive.
- Share reports only with people authorized to see the underlying test data.

## Credential handling

Prefer a credentials JSON file over inline `--credential` arguments for routine
use. Inline values can be recorded in shell history and may be visible in process
listings on some systems. Protect the credentials file with appropriate OS
permissions and do not commit it.

## Scope and limitations

Charon provides deterministic evidence-backed heuristics for authorization
analysis. A finding is a lead to validate, not a substitute for manual review,
application context, or a responsible disclosure process. Detection coverage and
false-positive/false-negative rates depend on the tested application, capture
quality, identity coverage, response semantics, and rule configuration. No
claim of complete authorization coverage is implied.

Charon is intended for authorized testing only. Stop testing if authorization
or scope is unclear, unexpected impact occurs, or test identities behave in an
unplanned way.
