# Part 2: Endpoint-policy evaluation

This evaluation compares Charon's deterministic run on the same eight VAmPI
cases with no policy config and with the optional endpoint policy file. It also
records a one-case cross-check against an independently labelled API security
lab. The original Part 1 raw report and Part 2 raw reports are unchanged; their
derived summaries now apply the revised ground truth (including the
inconclusive public user-list case). In particular,
[`raw/charon-report.json`](raw/charon-report.json) was not overwritten (its
SHA-256 remains
`907442d378c5aa4d6928a5a76fc299d0d87661585a62f2e5ac0ad5df4c9d3de0`).

## Run identity and files

| Item | Value |
| --- | --- |
| Evaluation date | 2026-10-13 |
| Charon version / commit | `0.1.0` / `20a65d65b1ecb11d39fdd483f7673bcfce3343e9` |
| VAmPI source | [`erev0s/VAmPI`](https://github.com/erev0s/VAmPI), commit `f16052dce83f05847133ec98f01c5193a41de7d8` |
| Runtime | Python `3.11.2`; Python VAmPI app bound to loopback; no Docker |
| Cases and replay identities | 8 baseline exchanges; Bob and admin replay credentials; 5 metric-eligible cases; 3 inconclusive |
| Mode | deterministic, no LLM |
| No-policy artifacts | [`raw/part2-no-policy/`](raw/part2-no-policy/) |
| With-policy artifacts | [`raw/part2-with-policy/`](raw/part2-with-policy/) |
| Policy file | [`vampi-endpoint-policy.json`](vampi-endpoint-policy.json) |

Both invocations used the pinned target and runner, which resets the disposable
VAmPI database and recreates the same synthetic cases. The no-policy command
omitted `--endpoint-policy`; the policy command passed
`--endpoint-policy docs/evaluation/vampi-endpoint-policy.json`. Captures and
live VAmPI tokens were temporary and removed after each run. The Part 2 raw
reports came from those executed runs; their derived summaries were
recalculated from the saved reports using the revised labels. All raw reports
remain unchanged.

## Side-by-side findings and metrics

The no-policy run reported **27 findings**. The configured run reported **22**;
**5 findings** were moved to the policy-declared audit section and excluded from
`findings` and `finding_count`. Both runs used the same **5 metric-eligible
cases**; the home route, user-list request, and profile lookup are inconclusive.
Exact counts and class-level ratios are from the two saved `run-summary.json`
files.

| Charon class / rule | No policy TP/FP/FN/TN | No policy precision / recall | With policy TP/FP/FN/TN | With policy precision / recall |
| --- | ---: | ---: | ---: | ---: |
| OWASP API1 BOLA — `authz.bola.cross-account-object-exposure` | `2/1/0/2` | `2/3` / `1` | `2/1/0/2` | `2/3` / `1` |
| OWASP API3 BOPLA — `authz.bopla.excessive-data-exposure` | `0/1/1/3` | `0` / `0` | `0/1/1/3` | `0` / `0` |
| OWASP API5 BFLA — `authz.bfla.privilege-transition` | `0/1/0/4` | `0` / N/A | `0/0/0/5` | N/A / N/A |
| Internal missing-authorization heuristic — `authz.missing-authz.no-authorization-header` | `0/1/0/4` | `0` / N/A | `0/1/0/4` | `0` / N/A |

N/A means the denominator is zero: the five-case set has no API5 or internal-
heuristic positive labels; with policy, API5 also has no predicted positives.
The internal missing-authorization heuristic is not an OWASP category (the
historical raw reports call it `API7`; official OWASP API Security Top 10
(2023) API7 is Server Side Request Forgery). These small-sample figures
describe this corpus only. Policy suppression is a caller-authored scope
decision, not evidence that a target's policy is correctly enforced.

### Policy declarations and affected cases

| Observed route | Declaration | Findings moved out of `findings` | Case result |
| --- | --- | --- | --- |
| `GET /users/v1` | `public` | 4: two API1 and two internal missing-authorization findings across the two replay identities | `users-list-public` is reported as `policy-declared`; no findings remain for this case (the case remains inconclusive for metrics) |
| `DELETE /users/v1/charon_eval_disposable` | `role-restricted`, allowed role `admin`, configured template `/users/v1/{username}` | 1 API5/BFLA finding | `admin-only-delete` is reported as `policy-declared`; no findings remain for this case |

The policy run contains two `policy-declared` entries, each with its matched
exchange ID and suppressed finding summaries. No other case changed class-level
observations:

| Case | No-policy observed classes | With-policy result |
| --- | --- | --- |
| `home-policy-unclear` | API1, API3, internal missing-authorization | API1, API3, internal missing-authorization; unchanged |
| `users-list-public` (inconclusive) | API1, internal missing-authorization | `policy-declared` (4 suppressed; still excluded from metrics) |
| `user-profile-policy-unclear` | API1, API3, internal missing-authorization | API1, API3, internal missing-authorization; unchanged |
| `debug-sensitive-data` | API1, internal missing-authorization | API1, internal missing-authorization; unchanged |
| `me-current-user` | none | none; unchanged |
| `book-cross-account` | API1, API3 | API1, API3; unchanged |
| `password-change-cross-user` | API1 | API1; unchanged |
| `admin-only-delete` | API5 | `policy-declared` (1 suppressed) |

The declarations record operator-supplied policy, not ground-truth labels.
VAmPI's pinned README permits minimal public information about dummy users, but
the runner-created Alice, Bob, and disposable accounts returned by the test are
outside a clearly established public-data scope; `users-list-public` therefore
remains inconclusive even when the run declares the route public. The
admin-only deletion declaration follows the README and OpenAPI. Source
references are retained in the policy config and
[`ground_truth.json`](ground_truth.json). `allowed_roles` is descriptive
metadata: Charon does not infer roles from credentials or prove the target
checks them. The API5 suppression removes an expected admin-vs-user transition
from findings because the route is explicitly declared role-restricted; it is
not a claim that VAmPI's role enforcement was independently verified.

## No-config byte-equivalence check

The preserved Part 1 report and the Part 2 no-policy report came from separate
captures, so their content-addressed finding/evidence IDs differ. Their
case-level observed classes and metric counts are the same after the ground-
truth revision. A historical no-config compatibility check compared the
pre-policy source at commit `642649d4572a902c5f0343c215b1918095278f63` with the
policy-enabled source at commit `20a65d65b1ecb11d39fdd483f7673bcfce3343e9` on
the exact same sanitized ShopAPI capture (SHA-256
`3be556aad333f51e9d7df0cb25fa62d297235fb65e79ad91a8c4ba88f09ec11e`) and the
same temporary Bob credential. Those deterministic JSON reports were
byte-identical: SHA-256
`3976337eb82fc19b72d3b0ecda43240dd0e4d5f80caefb2599a5726a00d85da5`, with 2
findings. That record predates report schema v2 and the taxonomy correction; it
is not a byte-equivalence claim for the current report format. The current test
suite separately checks that an empty policy config is a no-op. The credential
and temporary A/B reports were removed; the historical record is in
[`raw/part2-no-policy-byte-equivalence.json`](raw/part2-no-policy-byte-equivalence.json).

The Part 2 VAmPI no-policy report SHA-256 is
`fbceac32b7ead5cf8a5d6658fc7e997cf0a2047846b9a3930d25dab0ac58eaf0`; the
with-policy report SHA-256 is
`3753e98db0b118571611c84856da560b1293025a717780a24f1ab25a42783c61`. Their
full JSON is retained in the respective raw directories. The fresh VAmPI
capture run produces new content-addressed trace IDs, which is why its report
hash should not be compared as a byte-for-byte repeat of Part 1's separately
captured raw report.

## Independent second-API cross-check

A second target was checked before analysis to confirm it ran directly with
Python and did not require Docker. The pinned
[OWASP API Top 10 Security Lab](https://github.com/rangarajusaivivek/OWASP-API-Top10-Lab/tree/4ebf2b57abdab076d1bbc092132819925573cde1)
(ShopAPI) source is independently labelled intentionally vulnerable. Its
README labels `/api/orders/{id}` as API1 BOLA and gives `/api/orders/2` as the
cross-user order example; `vulnerable_api/app.py` states that the route does
not check order ownership. The exact source quotes and line references are in
[`second_api_ground_truth.json`](second_api_ground_truth.json).

Runtime verification used Python `3.11.2`, the repository's requirements in an
isolated virtual environment, a loopback-only Flask server, and a temporary
SQLite DB. No Docker was used. Observed controls were: health endpoint HTTP
200; unauthenticated `GET /api/orders/2` HTTP 401; Alice's request to the
Bob-owned order returned HTTP 200 with `user_id: 2`; Bob's owner-baseline
request also returned HTTP 200 with `user_id: 2`.

Charon then analyzed Alice's sanitized captured response and replayed it under
Bob's identity in deterministic mode. On the single source-labelled vulnerable
case, it emitted **2 findings**: one high-severity API1/BOLA finding matching
the independent label and one high-severity API3/BOPLA finding on the same
response. The single-case run has no labelled negative control, so precision
and recall are not calculated. The raw capture, report, observations, logs, and
exact summary are in [`raw/second-api/`](raw/second-api/); the report SHA-256 is
`80250de1fd86651e572f2e68ad02294b87c311f3ff21d965d1d6210464e28cba`.

## Code validation

On the current review-fix source, the full test suite passed (**310 passed**),
`ruff check .` passed, and strict mypy passed for 102 source files.
Both evaluation runners compiled and the ground-truth/policy JSON files parsed
successfully. The preserved Part 1 and Part 2 summaries were recalculated from
the unchanged historical raw reports; their report hashes were verified
unchanged. A fresh target evaluation was not available in this environment:
neither pinned target checkout nor its loopback server was present. Python 3.12
was also unavailable locally; CI results for the pushed changes are tracked
separately.

## Reproduce

Keep the pinned Python VAmPI process from [`SETUP.md`](SETUP.md) running on
`127.0.0.1:5000`, then run both commands from the Charon root. Choose fresh
output directories on subsequent runs to retain prior raw artifacts.

```bash
NO_POLICY_DIR="$(mktemp -d /tmp/charon-eval-no-policy.XXXXXX)"
WITH_POLICY_DIR="$(mktemp -d /tmp/charon-eval-with-policy.XXXXXX)"

VAMPI_DIR=/tmp/charon-eval-vampi \
  /tmp/charon-eval-env/bin/python docs/evaluation/run_eval.py \
  --base-url http://127.0.0.1:5000 \
  --vampi-dir /tmp/charon-eval-vampi \
  --output-dir "$NO_POLICY_DIR"

VAMPI_DIR=/tmp/charon-eval-vampi \
  /tmp/charon-eval-env/bin/python docs/evaluation/run_eval.py \
  --base-url http://127.0.0.1:5000 \
  --vampi-dir /tmp/charon-eval-vampi \
  --output-dir "$WITH_POLICY_DIR" \
  --endpoint-policy docs/evaluation/vampi-endpoint-policy.json
```

For the second API, clone and check out the pinned revision, install its
`requirements.txt` in an isolated Python environment, start it on loopback
with a temporary DB, and run
`/tmp/charon-eval-env/bin/python docs/evaluation/run_second_api_eval.py`.
See the runner and ground-truth JSON for its target path, default port, and
revision guard. Both runners refuse non-loopback targets and redirects outside
the original loopback origin, and refuse nonempty output directories.
