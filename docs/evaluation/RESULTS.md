# VAmPI evaluation results

These are the Part 1 VAmPI results. The original raw report is preserved; the
ground-truth scope and derived summaries/metrics have been revised where a
negative label was not defensible. See the [Part 2 endpoint-policy comparison
and independent second-API cross-check](POLICY_RESULTS.md) for the policy
reruns.

## Run identity

| Item | Recorded value |
| --- | --- |
| Evaluation date | 2026-10-13 |
| Charon version | `0.1.0` |
| Charon commit at run | `94b23bc4c0010a6c31637942c0d6e54f9bb0dcab` |
| VAmPI source | [`erev0s/VAmPI`](https://github.com/erev0s/VAmPI), commit `f16052dce83f05847133ec98f01c5193a41de7d8` |
| VAmPI OpenAPI version | `0.1` |
| Python | `3.11.2` |
| Charon replay transport | `httpx 0.28.1` |
| Target | `http://127.0.0.1:5000`, `vulnerable=1` |
| Mode | deterministic (`--mode deterministic`); no LLM mode |

VAmPI was cloned from GitHub and its `requirements.txt` installed from PyPI.
The app was run directly with Python, with a loopback-only launcher; Docker was
not used. The run used only this pinned VAmPI instance.

## Scope and measured metrics

The runner captured **8 baseline exchanges** and Charon replayed them with **2
credential identities**. The preserved raw Charon report contains **27
findings**. Three executed cases are now `inconclusive`: the home route, the
literal lookup of the newly registered synthetic user, and the public user
list. For the user list, the runner creates Alice, Bob, and a disposable user
before making the unauthenticated request; pinned VAmPI returns all database
users, including their email addresses. Its documentation permits public
access to basic information about dummy users but does not establish that these
newly created accounts are within that public-data scope. They are therefore
not defensibly `not_vulnerable` negatives. These 3 cases are excluded from
metrics; **5 cases are metric-eligible** and **9 additional cases were not
executed**. The raw report was not changed (SHA-256:
`907442d378c5aa4d6928a5a76fc299d0d87661585a62f2e5ac0ad5df4c9d3de0`).

Metrics count a finding once per `(test case, evaluation class)`, even when
both replay identities produce that class of finding. Official OWASP classes
are assessed against the source-defined expected classes; the missing-
authorization signal is separately identified as an internal Charon heuristic,
not an OWASP class. For each conclusive case, an observed class other than its
source-defined expected class is a false positive for that class. Inconclusive
and not-tested cases are excluded. Precision and recall below are exact
fractions, not rounded percentages. `N/A` means there were no positive cases
for that class; it is not a measured zero recall. The preserved historical raw
reports still encode the internal signal as `API7`; derived summaries map that
legacy code by rule ID to `internal:missing-authorization`. New Charon JSON
reports use `classification_scope` and do not put this signal in `owasp_class`.

| Charon class / rule | Test cases (positive; negative) | TP | FP | FN | TN | Precision (exact) | Recall (exact) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OWASP API1 BOLA — `authz.bola.cross-account-object-exposure` | 5 (2; 3) | 2 | 1 | 0 | 2 | `2/(2+1) = 2/3` | `2/(2+0) = 1` |
| OWASP API3 BOPLA — `authz.bopla.excessive-data-exposure` | 5 (1; 4) | 0 | 1 | 1 | 3 | `0/(0+1) = 0` | `0/(0+1) = 0` |
| OWASP API5 BFLA — `authz.bfla.privilege-transition` | 5 (0; 5) | 0 | 1 | 0 | 4 | `0/(0+1) = 0` | N/A (no positive cases) |
| Internal missing-authorization heuristic — `authz.missing-authz.no-authorization-header` | 5 (0; 5) | 0 | 1 | 0 | 4 | `0/(0+1) = 0` | N/A (no positive cases) |

These counts describe this five-case conclusive corpus only. The machine-readable
counts and case mappings are in [`raw/run-summary.json`](raw/run-summary.json);
source labels and exact quoted evidence are in
[`ground_truth.json`](ground_truth.json).

## Executed case outcomes

| Case | Source-audited expected result | Charon classes observed | Metric treatment |
| --- | --- | --- | --- |
| `home-policy-unclear` — `GET /` | Inconclusive; home operation is named, but access policy is unspecified | API1, API3, internal missing-authorization | Excluded |
| `users-list-public` — `GET /users/v1` | Inconclusive; the intended public-data scope does not clearly cover the three runner-created accounts returned by the route | API1, internal missing-authorization | Excluded |
| `user-profile-policy-unclear` — `GET /users/v1/charon_eval_alice` | Inconclusive; docs discuss dummy users, not this registered synthetic account | API1, API3, internal missing-authorization | Excluded |
| `debug-sensitive-data` — `GET /users/v1/_debug` | Vulnerable; VAmPI labels excessive data exposure (evaluated against API3) | API1, internal missing-authorization | API3 false negative; wrong-class API1/internal findings |
| `me-current-user` — `GET /me` | Not vulnerable for valid-token current-user access | None | No finding |
| `book-cross-account` — `GET /books/v1/charon_eval_alice_book` | Vulnerable; BOLA (evaluated against API1) | API1, API3 | API1 true positive; API3 false positive under the single-label ground truth |
| `password-change-cross-user` — `PUT /users/v1/charon_eval_bob/password` | Vulnerable; unauthorized password change (evaluated against API1) | API1 | API1 true positive |
| `admin-only-delete` — `DELETE /users/v1/charon_eval_disposable` | Not vulnerable; documented admin-only role boundary | API5 | API5 false positive |

The baseline status codes, in the same order, were `200`, `200`, `200`, `200`,
`200`, `200`, `204`, and `401`. Findings on all three inconclusive cases remain
visible in the observation record, but do not contribute to any metric. The
API3 finding on the book case is counted as a false positive because the
source-defined label for that test is BOLA; this is a single-label metric
mapping, not an assertion that the exposed `secret` is harmless.

## Source-label audit against the pinned VAmPI files

The quotes below are verbatim from README/OpenAPI at commit
[`f16052dce83f05847133ec98f01c5193a41de7d8`](https://github.com/erev0s/VAmPI/tree/f16052dce83f05847133ec98f01c5193a41de7d8).
Line numbers and the same full quotes are recorded per case in
[`ground_truth.json`](ground_truth.json). VAmPI does not assign Charon's OWASP
API category codes; API1/API3 are explicit evaluation mappings. The internal
missing-authorization heuristic is not an OWASP category. Historical raw reports
retain its old `API7` code; in OWASP API Security Top 10 (2023), API7 is Server
Side Request Forgery.

1. **`home-policy-unclear` — `inconclusive` (corrected from `not_vulnerable`).**
   README [line 25](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L25):
   `|     GET    |               /               |                     VAmPI home                     |`;
   OpenAPI [line 38](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L38):
   `      summary: VAmPI home`. These identify the route but say nothing about
   intentional public access, so the old negative label was unsupported.

2. **`users-list-public` — `inconclusive` (changed from `not_vulnerable`).**
   README [line 18](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L18):
   `VAmPI's flow of actions is going like this: an unregistered user can see minimal information about the dummy users included in the API. A user can register and then login to be allowed using the token received during login to post a book. For a book posted the data accepted are the title and a secret about that book. Each book is unique for every user and only the owner of the book should be allowed to view the secret.`
   README [line 27](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L27) and OpenAPI [line 67](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L67) identify `GET /users/v1` as displaying all users with basic information. However, the runner creates Alice, Bob, and a disposable account before the unauthenticated list call; the pinned implementation returns every database user, including those new records and their email addresses. The docs do not establish that those records are part of the intended public-data set or that exposing them is safe, so a `not_vulnerable` label is not defensible. The case remains executed but is marked `inconclusive` and excluded from metrics.

3. **`user-profile-policy-unclear` — `inconclusive` (corrected from `not_vulnerable`).**
   The README [line 18](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L18) limits its public-read statement to “minimal information about the dummy users included in the API.” The case instead queried a newly registered synthetic account. README [line 31](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L31) says `|     GET    |      /users/v1/{username}     |              Displays user by username             |`; OpenAPI [line 268](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L268) says `      description: Displays user by username`. Neither says whether this registered account should be publicly readable. The old negative label was unsupported for the exact case tested.

4. **`debug-sensitive-data` — `vulnerable` (VAmPI label: excessive data exposure; API3 is the evaluation mapping).**
   README [line 47](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L47):
   ` - Excessive Data Exposure through debug endpoint`. The corresponding OpenAPI description at [line 93](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L93) is `      description: Displays all details for all users`, and [line 114](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L114) exposes the `password:` response field. The API3 mapping is not a VAmPI-assigned label.

5. **`me-current-user` — `not_vulnerable` for the valid-token current-user test.**
   OpenAPI [line 218](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L218) requires `          - bearerAuth: []`; [line 222](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L222) says `        description: Displays information about the currently authenticated user`. The tested case used login-issued tokens; weak-signing-key forgery is a separate, untested case.

6. **`book-cross-account` — `vulnerable` (VAmPI BOLA label; API1 evaluation mapping).**
   README [line 45](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L45) says ` - Broken Object Level Authorization`. The README flow at [line 18](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L18) says “only the owner of the book should be allowed to view the secret.” OpenAPI [line 593](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L593) says `        Retrieves book by title along with secret. Only the owner may retrieve`, and [line 594](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L594) continues `        it`.

7. **`password-change-cross-user` — `vulnerable` (VAmPI unauthorized-password-change label; API1 evaluation mapping).**
   README [line 44](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L44) says ` - Unauthorized Password Change`; README [line 34](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L34) documents `PUT /users/v1/{username}/password`; OpenAPI [line 438](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L438) names the `username to update password` path parameter. API1 is the evaluation mapping; VAmPI does not assign an OWASP API code to this individual README label.

8. **`admin-only-delete` — `not_vulnerable` (documented intended role boundary).**
   README [line 32](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md#L32) says `|   DELETE   |      /users/v1/{username}     |       Deletes user by username (Only Admins)       |`; OpenAPI [line 351](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml#L351) documents `example: 'Only Admins may delete users!'` for the unauthorized response. The Alice-denied/admin-allowed transition is the documented policy boundary.

## VAmPI vulnerability labels not measured by this Charon run

VAmPI documents these vulnerabilities, but this deterministic Charon run did
not exercise their exploit conditions. The expected label is from VAmPI's docs;
**all metric cells are `TBD`, not zero**. These cases are excluded from the four
measured class tables above.

| VAmPI class / case | Source-defined expected result | Charon test status | TP | FP | FN | Precision | Recall |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| SQL injection — `GET /users/v1/{username}` | Vulnerable | Not tested (benign literal only) | TBD | TBD | TBD | TBD | TBD |
| Mass assignment — `POST /users/v1/register` | Vulnerable | Not tested (body properties not mutated) | TBD | TBD | TBD | TBD | TBD |
| User/password enumeration — `POST /users/v1/login` | Vulnerable | Not tested (distinct guesses not compared) | TBD | TBD | TBD | TBD | TBD |
| RegexDOS — `PUT /users/v1/{username}/email` | Vulnerable | Not tested (no pathological input sent) | TBD | TBD | TBD | TBD | TBD |
| Weak JWT signing key — protected `GET /me` | Vulnerable | Not tested (no token forgery) | TBD | TBD | TBD | TBD | TBD |
| Lack of resources / rate limiting — API-wide | Vulnerable | Not tested (no load or exhaustion run) | TBD | TBD | TBD | TBD | TBD |

The globally listed but untested `/books/v1` listing, `/books/v1` creation, and
`/createdb` setup operation are marked `inconclusive` in `ground_truth.json`;
the docs do not provide a sufficiently specific vulnerability label for those
operations in this authorization corpus.

## Reproduce and validate

From the Charon repository root, while the pinned VAmPI process is running on
loopback:

```bash
python3 -m venv /tmp/charon-eval-env
/tmp/charon-eval-env/bin/python -m pip install -e '.[replay]'
OUTPUT_DIR="$(mktemp -d /tmp/charon-eval-vampi.XXXXXX)"
VAMPI_DIR=/tmp/charon-eval-vampi \
  /tmp/charon-eval-env/bin/python docs/evaluation/run_eval.py \
  --base-url http://127.0.0.1:5000 \
  --vampi-dir /tmp/charon-eval-vampi \
  --output-dir "$OUTPUT_DIR"
```

See [`SETUP.md`](SETUP.md) for the pinned VAmPI clone, Python install,
loopback startup, and test-user setup commands. The runner resets the local
VAmPI database on each invocation. Raw Charon output is committed at
[`raw/charon-report.json`](raw/charon-report.json), with the verbose run log at
[`raw/charon-stderr.log`](raw/charon-stderr.log). The full Charon test suite was
run from the repository root with
`/tmp/charon-eval-env/bin/python -m pytest`: **279 passed in 1.17s** (logged in
[`raw/pytest.log`](raw/pytest.log)).
