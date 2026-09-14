# Baseline Measurements

This directory holds reproducible baseline measurements taken **before**
starting a Technical Debt (TD) item, so the item's effect can later be
compared against a real "before" snapshot instead of an assumption.

Per `PLATFORM_STRATEGY.md` §11: *"A metric without a reproducible
measurement method is not a metric. It is a wish."* Everything recorded
here was produced by actually running the built `arfa` binary against the
local `cmd/test-target` server — nothing in this directory is estimated,
inferred, or backfilled.

## 1. Field inspection (source of the metrics below)

Before writing the measurement script, the actual `scan_results.json`
produced by:

```bash
./arfa -target http://127.0.0.1:18080 -payload-dir ./payloads-database/PayloadsAllTheThings-master \
  -mode quick -workers 20 -rate 100 -max-pages 30 -out <dir> -i-have-authorization
```

was inspected directly (build: `go build ./cmd/arfa ./cmd/test-target`,
commit `933309e` — see `td01-pre-baseline-2026-09-15.json` for the exact
hash and full raw run data). This is the authoritative field inventory;
`pkg/report/report.go` (`JSON()`) is a plain `json.MarshalIndent` of
`models.ScanResult` with no allowlist, so what's below is what the struct
tags in `pkg/models/models.go` actually produce, confirmed against a real
run rather than assumed from the struct definition alone.

### Present at the top level

| Field | Notes |
|---|---|
| `schema_version` | `"arfa.scan/v1"` |
| `target`, `scope`, `started_at`, `mode` | as configured/derived |
| `reachability` | status, reason, resolved_ips, selected_url, checks[] |
| `stats` | see below |
| `findings` | array (see below); `null` if preflight/crawl never reached the job phase |
| `coverage` | present when the job phase ran; **omitted** (`omitempty`) when empty |
| `next_actions` | **omitted** (`omitempty`) when the planner has nothing actionable — did not appear in any baseline run, since all 3 findings resolved to CONFIRMED and nothing else was NotAttempted/Inconclusive against this target |

### `stats` object — present fields

`pages`, `endpoints`, `parameters`, `requests`, `errors`, `duration_ms`,
`adaptive_budget`, `jobs_planned`.

`jobs_capped` and `time_budget_exhausted` are `omitempty` bools — present
in the JSON only when `true`. They were `false` in every baseline run and
so do not appear in the raw `scan_results.json`; the baseline script
still records them explicitly (defaulting to `false`) so the aggregated
report is self-describing.

### `findings[]` object — present fields

`id`, `category`, `name`, `severity`, `cvss`, `confidence`, `endpoint`,
`parameter`, `payload`, `encoding`, `evidence`, `poc`, `impact`,
`remediation`, `status`, `verification_status`, `verification_detail`,
`verification_confidence`, `verification_confidence_reason`,
`evidence_detail` (nested: timestamp, endpoint, parameter, category,
request_method, request_url, response_status, response_snippet,
response_hash, verification_trace[]).

`verification_caveat` is `omitempty` and only appears on a `CONFIRMED`
finding from a detector implementing `CaveatProvider` (currently XSS
only, per TD #10) — confirmed present on the XSS finding in the baseline
run and absent on the SQLi/LFI findings.

### Missing / not emitted anywhere in the envelope

- **`max_pages`, `workers`, `rate`, `timeout`** — these are scan
  **configuration inputs** (CLI flags), not scan **output**. None of them
  are echoed anywhere into `scan_results.json`. Only `mode` is echoed.
  This means a `scan_results.json` file alone cannot tell you what
  `-max-pages`/`-workers`/`-rate`/`-timeout` a given run used — that
  context only exists in whatever invoked the scan (e.g. this baseline
  script's own aggregated output records the invocation config
  separately, under `config`, precisely because the scanner doesn't).
- No per-endpoint or per-page timing breakdown, no per-detector-category
  request/finding breakdown, no memory/CPU metrics. `pkg/scanner` does
  not currently instrument any of this (see `pkg/scanner/scanner.go`) and
  none of it was added for this baseline task — this is only a
  documentation gap identified during inspection, not something this
  task implements. No instrumentation was added anywhere under `pkg/`.

This is a snapshot at commit `933309e` (see the baseline JSON files in
this directory, e.g. `td01-pre-baseline-2026-09-15.json`, for the exact
commit hash of each recorded run).

## 2. Running a baseline

```bash
# from repo root, after `git checkout` to the commit you want to baseline
RUNS=3 PAYLOAD_DIR="$(pwd)/payloads-database/PayloadsAllTheThings-master" \
  scripts/run_baseline.sh <name>
```

This is the exact command used to produce
`td01-pre-baseline-2026-09-15.json` in this directory (with `<name>` set
to `td01-pre-baseline-2026-09-15`).

`PAYLOAD_DIR` defaults to
`$ROOT/payloads-database/PayloadsAllTheThings-master` if not set — pass
it explicitly whenever that directory isn't already present at the
default path (it is gitignored, per the project's payload-corpus policy
in `README.md`). The script builds `cmd/test-target` and `cmd/arfa` into
a temp dir (does not touch any repo-tracked binary), starts the test
target on `127.0.0.1:18080`, and for each of the `RUNS` repetitions runs
exactly:

```bash
arfa -target "$TARGET" -payload-dir "$PAYLOAD_DIR" \
  -mode "$MODE" -workers "$WORKERS" -rate "$RATE" -max-pages "$MAX_PAGES" \
  -out <per-run temp dir> -i-have-authorization
```

then writes the aggregated result to `docs/baselines/<name>.json` — the
filename is exactly `<name>.json`; the script never appends a date, so
`<name>` must be the full filename stem you want (as in the example
above).

Fixed configuration (override via env vars — see the script header):

```text
target:      http://127.0.0.1:18080
payload-dir: ./payloads-database/PayloadsAllTheThings-master
mode:        quick
workers:     20
rate:        100
max-pages:   30
```

This matches the exact CLI invocation used in this task and the
"Verified local target" configuration recorded in
`ARFA_MASTER_CONTEXT.md` §4, so results here are directly comparable to
that historical reference point.

## 3. Interpreting a baseline file

Each `docs/baselines/<name>.json` contains:

- `commit_hash` / `commit_dirty` — exact source state measured.
- `config` — the invocation configuration (see the "missing fields" note
  above for why this has to be recorded out-of-band).
- `runs[]` — one entry per repetition, with only the fields listed in §1.
- `summary` — min/max/mean/median across runs, only for fields that were
  actually numeric in every run.
- `non_deterministic_fields_observed` — flags if `findings_count` or
  `requests` varied across runs against the same target/config (an empty
  list means all runs were identical on those fields).

## 4. Known environment caveat (unrelated to TD #1/#2)

`pkg/payloads` has a baseline test failure in sandboxes without the
external `payloads-database/` directory present — this is a pre-existing
sandbox artifact (see project memory), not something this task's changes
affect, and is unrelated to the crawler/`pkg/scanner` metrics recorded
here.
