# Validation Plan

This plan describes how to validate Charon's deterministic authorization
analysis without probing third-party systems. Run the tests against local,
synthetic fixtures or an explicitly authorized test environment.

## 1. Reproducibility

- Install the development dependencies with `python -m pip install -e ".[dev]"`.
- Run `pytest` twice on the same commit and compare test outcomes.
- Run `ruff check .` and `mypy .`.
- Record the Python version, dependency lock state, command, and commit SHA.

## 2. Controlled authorization matrix

Use a local mock API with two test identities (owner and non-owner) and seeded
synthetic objects. Include positive and negative cases:

| Case | Owner identity | Other identity | Expected interpretation |
|---|---|---|---|
| Public resource | Allowed | Allowed | No cross-account authorization issue from access alone |
| Private resource | Allowed | Denied | Expected owner-only behavior |
| Broken object authorization | Allowed | Allowed to read a private object | Candidate BOLA/IDOR finding |
| Function authorization gap | Privileged function succeeds | Lower-privilege function denied | Candidate BFLA finding |
| Property exposure | Sensitive property absent/filtered for lower privilege | Sensitive property appears for lower privilege | Candidate BOPLA signal, subject to policy context |
| Authentication required | Authenticated request succeeds | Unauthenticated request denied | Expected access boundary |

These expected interpretations are a test-design guide, not a statement that
every case is currently covered by the implementation.

## 3. Metrics worth publishing

Do not publish detection-rate claims until you have a labeled corpus and can
reproduce the measurements. At minimum report:

- True positives, false positives, true negatives, false negatives.
- Precision = TP / (TP + FP), when the denominator is non-zero.
- Recall = TP / (TP + FN), when the denominator is non-zero.
- Test-case count and coverage by rule, identity pair, response type, and HTTP
  status behavior.
- Runtime and failures for the same fixture set and machine.

Keep the fixture definitions, expected outputs, run command, and result summary
under version control. Separate unit-test pass rate from vulnerability-detection
quality; they measure different things.

## 4. Safety checks

- Make sure test hosts are local fixtures or expressly authorized targets.
- Verify that persisted replay artifacts contain no test credential values.
- Review captures and reports for sensitive bodies and query parameters.
- Confirm disabled/enriched annotation behavior cannot create or suppress
  deterministic findings.
