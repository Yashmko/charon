# Evaluation limitations

## What this run found and missed

The run was limited to eight executed HTTP exchanges against the pinned,
loopback-only VAmPI instance, using one baseline account (`charon_eval_alice`)
and two replay identities (`charon_eval_bob` and VAmPI's seeded `admin`). Six
source-audited cases contribute to metrics; the home response and a literal
lookup of the newly registered synthetic profile are inconclusive and
excluded. The detailed output is in [`raw/charon-report.json`](raw/charon-report.json)
and [`raw/run-summary.json`](raw/run-summary.json).

- **Found the two API1 positives:** cross-account retrieval of Alice's book and
  Alice-authenticated password change for Bob both produced API1 findings.
- **Missed the source-labeled API3 debug exposure:** `GET /users/v1/_debug`
  returned HTTP 200 with the all-users debug response, but Charon emitted API1
  and API7 findings, not API3. This is the one API3 false negative in the
  measured set. The current BOPLA rule counts direct top-level response fields;
  the debug response wraps its records under a single `users` key, below the
  rule's two-field threshold.
- **Public/ambiguous access cases generated findings:** the source audit
  supports a `not_vulnerable` label for the documented basic-information users
  list, which generated API1 and API7 findings. The home operation and literal
  lookup of the newly registered synthetic profile also generated findings
  (API1/API3/API7), but the pinned README/OpenAPI do not establish their access
  policies for those exact requests. Those two cases are now `inconclusive`,
  not metric false positives. The detector still treats identical
  cross-identity responses and a missing baseline `Authorization` header as
  signals without endpoint policy context.
- **Debug endpoint class mismatch:** the source labels the debug issue as
  excessive data exposure; the run emitted API1 and API7 instead of the
  expected API3. Under the source-defined, single-label ground truth these are
  wrong-class findings.
- **A documented role check generated a BFLA false positive:** Alice's delete
  request was denied (401) and the admin replay was allowed. VAmPI's OpenAPI
  description explicitly says only admins may delete users, so this is the
  intended role distinction, not a vulnerability. The tested user was a
  disposable synthetic account.
- **The book case also emitted API3:** the ground-truth source labels that
  operation as BOLA/API1. The API3 count therefore treats this as a wrong-class
  finding; this narrow label accounting does not claim that the exposed `secret`
  property is harmless.

These are observations from the executed run, not claims that all findings
would be false positives in a different application or policy.

## Not tested

The machine-readable ground truth has 17 cases: 8 were executed (6
metric-eligible and 2 inconclusive), and 9 were not executed. In particular,
this run did **not** test:

- SQL injection (the captured username was a benign literal; no SQLi probe was
  generated).
- Mass assignment (the registration body was not mutated to set `admin`).
- User/password enumeration (no alternate username/password guesses were
  compared).
- RegexDOS (no pathological input was sent; it could stall the target).
- JWT weak-key forgery (only login-issued tokens were used).
- Lack of resources/rate limiting (no load or resource-exhaustion test was
  run).
- The access-control policy for global `GET /books/v1`, or stateful
  `POST /books/v1`; VAmPI's docs do not assign a specific vulnerability label
  to those cases.
- `GET /createdb` as a target operation; it is only used as test setup and
  resets the database.

The six VAmPI vulnerabilities listed in the first six bullets have source
labels in `ground_truth.json`, but their TP/FP/FN/precision/recall cells remain
**TBD** because this Charon run did not exercise them. TBD is not zero. The
current `charon analyze` flow replays captured requests; it does not mutate
request bodies, path values, JWTs, or request rates to create those probes.
No Charon detection code was changed for this evaluation.

To rerun the executed subset on a laptop, start the pinned Python VAmPI exactly
as shown in [`SETUP.md`](SETUP.md), then run this command from the Charon root:

```bash
VAMPI_DIR=/tmp/charon-eval-vampi \
  /tmp/charon-eval-env/bin/python docs/evaluation/run_eval.py \
  --base-url http://127.0.0.1:5000 \
  --vampi-dir /tmp/charon-eval-vampi \
  --output-dir docs/evaluation/raw
```

That command does not test the TBD classes. Testing them requires separate
class-specific probes; no ReDoS or load-generating command is provided here
because it could hang or exhaust even the local target. Do not point any of
these tests at a non-local service.

## Sample-size and method caveats

- There are 8 executed cases, but only 6 conclusive metric cases, with one
  baseline account and two replay identities. Per-class denominators are small;
  these exact ratios describe this corpus only and should not be generalized
  as expected production precision or recall.
- There are no source-labeled positive API5 or API7 cases in this eight-case
  set. Their recall is therefore **N/A**, not zero. API5/API7 precision is
  affected only by the observed false positives.
- The 27 raw findings include findings from both replay identities and several
  classes on the same exchange. Metrics deduplicate to one `(case, class)` pair
  as documented in `ground_truth.json`; they are not a count of raw report
  entries.
- VAmPI ran with `vulnerable=1` only; no secure (`vulnerable=0`) instance was
  tested. Conclusive non-vulnerable cases are the documented basic-information
  users list, the valid-token current-user endpoint, and the admin-only delete
  policy within the same instance. The home and synthetic-profile observations
  are excluded because their access policies are not established by the pinned
  source.
- The password-change replay uses only synthetic accounts and a fixed
  synthetic password. The admin delete case targets a disposable user. Each
  runner invocation resets the VAmPI database before recreating the test data.
- The raw report and summary are retained. Raw input captures and live bearer
  tokens are not persisted: the debug response contains synthetic plaintext
  passwords, and the runner removes its temporary capture/credential files
  after Charon completes.