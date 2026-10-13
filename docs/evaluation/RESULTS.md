# VAmPI evaluation results

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
not used. The run used only this VAmPI instance.

## Measured metrics

The runner loaded **8 baseline exchanges** and **2 replay credentials**. Charon's
raw deterministic report contained **27 findings**. For metrics, a finding is
counted once per `(test case, OWASP class)` even when both replay identities
produce the same class of finding. Cases are evaluated against the single
source-defined expected class: a finding in another class is a false positive
for that other class. Precision and recall below are exact fractions, not
rounded percentages. `N/A` means there were no positive cases for that class;
it is not a measured zero recall.

| Charon class / rule | Test cases (positive; negative) | TP | FP | FN | TN | Precision (exact) | Recall (exact) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| API1 BOLA — `authz.bola.cross-account-object-exposure` | 8 (2; 6) | 2 | 4 | 0 | 2 | `2/(2+4) = 1/3` | `2/(2+0) = 1` |
| API3 BOPLA — `authz.bopla.excessive-data-exposure` | 8 (1; 7) | 0 | 3 | 1 | 4 | `0/(0+3) = 0` | `0/(0+1) = 0` |
| API5 BFLA — `authz.bfla.privilege-transition` | 8 (0; 8) | 0 | 1 | 0 | 7 | `0/(0+1) = 0` | N/A (no positive cases) |
| API7 missing-authorization signal — `authz.missing-authz.no-authorization-header` | 8 (0; 8) | 0 | 4 | 0 | 4 | `0/(0+4) = 0` | N/A (no positive cases) |

These are counts over this eight-case corpus only. The labels and metric rules
are in [`ground_truth.json`](ground_truth.json); the complete machine-readable
counts are in [`raw/run-summary.json`](raw/run-summary.json).

## Case-level outcomes

| Case | Expected | Charon classes observed | Outcome under the source label |
| --- | --- | --- | --- |
| `home-public` — `GET /` | Not vulnerable; public home control | API1, API3, API7 | False positive for all three classes |
| `users-list-public` — `GET /users/v1` | Not vulnerable; documented public basic information | API1, API7 | False positive for API1 and API7 |
| `user-profile-public` — `GET /users/v1/charon_eval_alice` | Not vulnerable for this benign literal lookup; public minimal profile | API1, API3, API7 | False positive for all three classes |
| `debug-sensitive-data` — `GET /users/v1/_debug` | Vulnerable; VAmPI labels excessive data exposure (API3) | API1, API7 | API3 false negative; API1/API7 wrong-class findings |
| `me-current-user` — `GET /me` | Not vulnerable for valid-token current-user access | None | No finding |
| `book-cross-account` — `GET /books/v1/charon_eval_alice_book` | Vulnerable; BOLA (API1) | API1, API3 | API1 true positive; API3 false positive under the single-label ground truth |
| `password-change-cross-user` — `PUT /users/v1/charon_eval_bob/password` | Vulnerable; unauthorized password change mapped to BOLA (API1) | API1 | API1 true positive |
| `admin-only-delete` — `DELETE /users/v1/charon_eval_disposable` | Not vulnerable; documented admin-only role boundary | API5 | API5 false positive |

The endpoint-level baseline status codes were, in the same cases: `200`, `200`,
`200`, `200`, `200`, `200`, `204`, and `401`, respectively. The `API3` finding
on the book case is counted as a false positive because VAmPI's source label for
that test is BOLA; it is an observed category mismatch, not an assertion that
the exposed `secret` is harmless.

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

## Reproduce

From the Charon repository root, while the pinned VAmPI process is running on
loopback:

```bash
python3 -m venv /tmp/charon-eval-env
/tmp/charon-eval-env/bin/python -m pip install -e '.[replay]'
VAMPI_DIR=/tmp/charon-eval-vampi \
  /tmp/charon-eval-env/bin/python docs/evaluation/run_eval.py \
  --base-url http://127.0.0.1:5000 \
  --vampi-dir /tmp/charon-eval-vampi \
  --output-dir docs/evaluation/raw
```

See [`SETUP.md`](SETUP.md) for the pinned VAmPI clone, Python install,
loopback startup, and test-user setup commands. The runner resets the local
VAmPI database on each invocation. Raw Charon output is committed at
[`raw/charon-report.json`](raw/charon-report.json), with the verbose run log at
[`raw/charon-stderr.log`](raw/charon-stderr.log).