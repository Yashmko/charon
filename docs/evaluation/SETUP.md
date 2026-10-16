# VAmPI evaluation setup

This evaluation uses the Python version of VAmPI, not Docker. The tested VAmPI
checkout is pinned to Git revision
`f16052dce83f05847133ec98f01c5193a41de7d8` (its OpenAPI
`info.version` is `0.1`). VAmPI is cloned outside this repository; no VAmPI
source files are copied into Charon.

> **Local-only / destructive setup:** VAmPI is intentionally vulnerable and
> runs with Flask's debug mode enabled. The launcher below binds it only to
> `127.0.0.1`. The evaluation runner calls `GET /createdb`, which drops and
> recreates the VAmPI database, then creates synthetic test users. Use only a
> disposable VAmPI checkout/database. Do not expose the app to a network.

## 1. Install Charon's replay extra

Run from the Charon repository root. A separate virtual environment keeps the
VAmPI and Charon dependencies isolated.

```bash
cd /path/to/charon
python3 -m venv /tmp/charon-eval-env
/tmp/charon-eval-env/bin/python -m pip install -e '.[replay]'
```

## 2. Clone and install VAmPI

```bash
git clone https://github.com/erev0s/VAmPI.git /tmp/charon-eval-vampi
git -C /tmp/charon-eval-vampi checkout f16052dce83f05847133ec98f01c5193a41de7d8
python3 -m venv /tmp/charon-eval-vampi-venv
/tmp/charon-eval-vampi-venv/bin/python -m pip install \
  -r /tmp/charon-eval-vampi/requirements.txt
```

## 3. Start VAmPI on loopback

Run in a terminal and leave it open. This uses the checked-in launcher solely
to override VAmPI's `0.0.0.0` Flask bind to `127.0.0.1` and disable the debug
reloader; it does not patch or copy VAmPI source. The vulnerable setting is
explicit, and the token lifetime is increased to keep the local replay run
within a stable test window.

```bash
cd /path/to/charon
export CHARON_ROOT="$(pwd)"
cd /tmp/charon-eval-vampi
vulnerable=1 tokentimetolive=3600 \
  /tmp/charon-eval-vampi-venv/bin/python \
  "$CHARON_ROOT/docs/evaluation/start_vampi_local.py" \
  "$PWD/app.py"
```

The server must report `Running on http://127.0.0.1:5000`. In a second
terminal, confirm the vulnerable switch:

```bash
curl -fsS http://127.0.0.1:5000/
```

The response must contain `"vulnerable":1`.

## 4. Test users and setup requests

`GET /createdb` drops and repopulates the database. It seeds VAmPI's built-in
`admin` account (`admin` / `pass1`). These are the exact synthetic accounts
used by the evaluation runner; the runner creates them itself on every run.
The manual requests are included for inspection and should not be run just
before the runner, since the runner resets the database again.

```bash
BASE=http://127.0.0.1:5000

# Destructive: rebuilds the disposable local VAmPI database.
curl -fsS "$BASE/createdb"

curl -fsS -X POST "$BASE/users/v1/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"charon_eval_alice","password":"CharonEvalAlicePassword1","email":"charon-alice@example.test"}'

curl -fsS -X POST "$BASE/users/v1/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"charon_eval_bob","password":"CharonEvalBobPassword1","email":"charon-bob@example.test"}'

curl -fsS -X POST "$BASE/users/v1/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"charon_eval_disposable","password":"CharonEvalDisposablePassword1","email":"charon-disposable@example.test"}'
```

The runner logs in as Alice for the baseline captures, then as Bob and the
seeded admin for cross-identity replays. It also creates Alice's synthetic
book, changes only Bob's synthetic password as the password-change probe, and
uses the disposable user for the admin-only delete control. The delete replay
removes only that disposable account.

## 5. Run the evaluation

From the Charon repository root, in the second terminal, with the Charon
virtual environment installed above:

```bash
cd /path/to/charon
OUTPUT_DIR="$(mktemp -d /tmp/charon-eval-vampi.XXXXXX)"
VAMPI_DIR=/tmp/charon-eval-vampi \
  /tmp/charon-eval-env/bin/python docs/evaluation/run_eval.py \
  --base-url http://127.0.0.1:5000 \
  --vampi-dir /tmp/charon-eval-vampi \
  --output-dir "$OUTPUT_DIR"
```

The runner refuses non-loopback URLs, redirects outside the original loopback
origin, and a VAmPI Git revision other than the pinned commit. It runs Charon
with `--mode deterministic`; there is no LLM mode in this run. The output
directory receives `charon-report.json` (the raw Charon JSON report),
`run-summary.json` (case-level predictions and exact metrics), and Charon's
stdout/stderr logs. Captures and the short-lived bearer tokens are kept in a
temporary directory and removed after the run; the captured debug response
contains synthetic plaintext test passwords, so raw captures are deliberately
not persisted. The runner refuses any nonempty output directory, including the
checked-in historical `docs/evaluation/raw`; create a new empty directory for
every run.

A second invocation repeats the database reset and test-data setup. To rerun,
use the same commands above with a newly created output directory while the
loopback VAmPI process is running.

## 6. Optional-policy comparison and independent second API

The Part 2 comparison uses the same VAmPI runner and pinned target. Run once
without `--endpoint-policy` and once with
`--endpoint-policy docs/evaluation/vampi-endpoint-policy.json`; use distinct
output directories so no raw run is overwritten. Exact commands and measured
results are in [`POLICY_RESULTS.md`](POLICY_RESULTS.md).

The independent API check uses the Python-only ShopAPI target pinned in
[`second_api_ground_truth.json`](second_api_ground_truth.json). It was verified
without Docker, using Python `3.11.2`, an isolated virtual environment, and a
temporary SQLite database outside the source checkout. To reproduce it:

```bash
git clone https://github.com/rangarajusaivivek/OWASP-API-Top10-Lab.git \
  /tmp/charon-eval-owasp-api-top10-lab
git -C /tmp/charon-eval-owasp-api-top10-lab checkout \
  4ebf2b57abdab076d1bbc092132819925573cde1
python3 -m venv /tmp/charon-eval-owasp-api-env
/tmp/charon-eval-owasp-api-env/bin/python -m pip install \
  -r /tmp/charon-eval-owasp-api-top10-lab/requirements.txt
```

Start the lab from its `vulnerable_api` directory. This invokes Flask directly,
sets a disposable DB path before initialization, disables debug/reload, and
binds only to loopback; Docker is not involved.

```bash
cd /tmp/charon-eval-owasp-api-top10-lab/vulnerable_api
/tmp/charon-eval-owasp-api-env/bin/python -c \
  'import app; app.DB_PATH="/tmp/charon-eval-owasp-api.db"; app.init_db(); app.app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)'
```

In another terminal, from the Charon repository root, run the pinned second-API
case. The runner verifies the source revision, accepts loopback URLs only,
blocks redirects outside the original loopback origin, and refuses nonempty
output directories. Choose a fresh output directory for any later rerun.

```bash
cd /path/to/charon
OUTPUT_DIR="$(mktemp -d /tmp/charon-eval-shopapi.XXXXXX)"
/tmp/charon-eval-env/bin/python docs/evaluation/run_second_api_eval.py \
  --base-url http://127.0.0.1:5001 \
  --target-dir /tmp/charon-eval-owasp-api-top10-lab \
  --output-dir "$OUTPUT_DIR"
```

Only seeded synthetic users and order data are used. The runner persists a
sanitized Alice capture and report; it keeps live bearer tokens in a temporary
file and removes them after analysis. Stop the local Flask process after the
check.