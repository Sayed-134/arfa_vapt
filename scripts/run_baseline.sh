#!/usr/bin/env bash
# run_baseline.sh — Pre-TD baseline measurement harness.
#
# Runs the arfa CLI N times (default 3) against the local verified test
# target with a fixed, documented configuration, and aggregates ONLY the
# fields that pkg/report.JSON actually emits into scan_results.json today
# (verified by direct inspection — see docs/baselines/README.md). It does
# not invent, estimate, or backfill any metric that the scanner does not
# itself report.
#
# Modeled on scripts/run_e2e_regression.sh's build/launch/cleanup pattern
# so both scripts behave consistently in CI and locally.
#
# Usage:
#   scripts/run_baseline.sh [NAME]
#
#   NAME    Output filename (without extension): docs/baselines/<NAME>.json
#           The date is never auto-appended — pass the full name you want,
#           e.g. "td01-pre-baseline-2026-09-15". Defaults to "baseline".
#
# Environment overrides:
#   RUNS          Number of scan repetitions (default: 3)
#   PAYLOAD_DIR   Payload repository root (default: ./payloads-database/PayloadsAllTheThings-master)
#   PYTHON_BIN    Python interpreter used for JSON extraction (default: python3)
#   TARGET        Scan target (default: http://127.0.0.1:18080)
#   MODE          Scan mode (default: quick)
#   WORKERS       Worker count (default: 20)
#   RATE          Requests/sec (default: 100)
#   MAX_PAGES     Crawler page limit (default: 30)
#
# This script does not modify any file under pkg/, cmd/, or the frozen
# architecture documents. It only builds ephemeral binaries into a temp
# directory and writes its aggregated result under docs/baselines/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:-baseline}"
RUNS="${RUNS:-3}"
PAYLOAD_DIR="${PAYLOAD_DIR:-$ROOT/payloads-database/PayloadsAllTheThings-master}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
TARGET="${TARGET:-http://127.0.0.1:18080}"
MODE="${MODE:-quick}"
WORKERS="${WORKERS:-20}"
RATE="${RATE:-100}"
MAX_PAGES="${MAX_PAGES:-30}"

TMPDIR="$(mktemp -d)"
SERVER_PID=""
export GOCACHE="${GOCACHE:-$TMPDIR/go-build-cache}"

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

on_error() {
  status=$?
  echo "===== BASELINE FAILURE ====="
  echo "exit_code=$status"
  echo "===== TEST TARGET LOG ====="
  cat "$TMPDIR/test-target.log" 2>/dev/null || true
  exit "$status"
}
trap on_error ERR

cd "$ROOT"

if [[ ! -d "$PAYLOAD_DIR" ]]; then
  echo "Error: payload directory not found: $PAYLOAD_DIR" >&2
  echo "Set PAYLOAD_DIR or place PayloadsAllTheThings at the default path." >&2
  exit 1
fi

COMMIT_HASH="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
COMMIT_DIRTY="$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null | grep -q . && echo true || echo false)"

echo "[baseline] building test-target and arfa..."
go build -o "$TMPDIR/test-target" ./cmd/test-target
go build -o "$TMPDIR/arfa" ./cmd/arfa

echo "[baseline] starting local test-target..."
"$TMPDIR/test-target" >"$TMPDIR/test-target.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 80); do
  if curl --silent --fail "$TARGET/clean" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl --silent --fail "$TARGET/clean" >/dev/null

RUNS_JSON="$TMPDIR/runs.json"
echo "[]" > "$RUNS_JSON"

for i in $(seq 1 "$RUNS"); do
  echo "[baseline] run $i/$RUNS..."
  RUN_OUT="$TMPDIR/run-$i"
  RUN_START_EPOCH_MS=$(($(date +%s%N) / 1000000))
  "$TMPDIR/arfa" \
    -target "$TARGET" \
    -payload-dir "$PAYLOAD_DIR" \
    -mode "$MODE" -workers "$WORKERS" -rate "$RATE" -max-pages "$MAX_PAGES" \
    -out "$RUN_OUT" -i-have-authorization
  RUN_END_EPOCH_MS=$(($(date +%s%N) / 1000000))

  "$PYTHON_BIN" - "$RUN_OUT/scan_results.json" "$RUNS_JSON" "$i" "$RUN_START_EPOCH_MS" "$RUN_END_EPOCH_MS" <<'PY'
import json
import sys

result_path, runs_path, run_index, start_ms, end_ms = sys.argv[1:6]

with open(result_path, encoding="utf-8") as f:
    r = json.load(f)

stats = r.get("stats", {})
findings = r.get("findings") or []
coverage = r.get("coverage") or []
next_actions = r.get("next_actions") or []

# Only fields verified present in scan_results.json (see
# docs/baselines/README.md "Fields inspected" section) are extracted here.
# Nothing below is estimated or backfilled.
entry = {
    "run": int(run_index),
    "wall_clock_ms": int(end_ms) - int(start_ms),
    "schema_version": r.get("schema_version"),
    "mode": r.get("mode"),
    "reachability_status": r.get("reachability", {}).get("status"),
    "stats": {
        "pages": stats.get("pages"),
        "endpoints": stats.get("endpoints"),
        "parameters": stats.get("parameters"),
        "requests": stats.get("requests"),
        "errors": stats.get("errors"),
        "duration_ms": stats.get("duration_ms"),
        "adaptive_budget": stats.get("adaptive_budget"),
        "jobs_planned": stats.get("jobs_planned"),
        "jobs_capped": stats.get("jobs_capped", False),
        "time_budget_exhausted": stats.get("time_budget_exhausted", False),
    },
    "findings_count": len(findings),
    "findings_by_category": sorted({f.get("category") for f in findings}),
    "coverage_entries": len(coverage),
    "next_actions_count": len(next_actions),
}

with open(runs_path, encoding="utf-8") as f:
    runs = json.load(f)
runs.append(entry)
with open(runs_path, "w", encoding="utf-8") as f:
    json.dump(runs, f, indent=2)
PY
done

OUT_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE="$ROOT/docs/baselines/${NAME}.json"
mkdir -p "$ROOT/docs/baselines"

"$PYTHON_BIN" - "$RUNS_JSON" "$OUT_FILE" "$COMMIT_HASH" "$COMMIT_DIRTY" "$OUT_TIMESTAMP" "$TARGET" "$MODE" "$WORKERS" "$RATE" "$MAX_PAGES" <<'PY'
import json
import statistics
import sys

runs_path, out_path, commit_hash, commit_dirty, timestamp, target, mode, workers, rate, max_pages = sys.argv[1:11]

with open(runs_path, encoding="utf-8") as f:
    runs = json.load(f)

def series(key_path):
    vals = []
    for run in runs:
        v = run
        for k in key_path:
            v = v.get(k) if isinstance(v, dict) else None
            if v is None:
                break
        if isinstance(v, (int, float)):
            vals.append(v)
    return vals

def summarize(vals):
    if not vals:
        return None
    return {
        "min": min(vals),
        "max": max(vals),
        "mean": round(statistics.fmean(vals), 2),
        "median": statistics.median(vals),
        "n": len(vals),
    }

summary = {
    "requests": summarize(series(["stats", "requests"])),
    "duration_ms": summarize(series(["stats", "duration_ms"])),
    "wall_clock_ms": summarize(series(["wall_clock_ms"])),
    "findings_count": summarize(series(["findings_count"])),
    "coverage_entries": summarize(series(["coverage_entries"])),
    "adaptive_budget": summarize(series(["stats", "adaptive_budget"])),
    "jobs_planned": summarize(series(["stats", "jobs_planned"])),
}

# Flag any non-determinism across runs so a reader does not have to
# eyeball the runs[] array to notice it.
non_deterministic_fields = []
for field in ("findings_count", "requests"):
    key_path = ["stats", field] if field == "requests" else [field]
    vals = series(key_path)
    if len(set(vals)) > 1:
        non_deterministic_fields.append(field)

doc = {
    "task": "TD #1 pre-implementation baseline",
    "commit_hash": commit_hash,
    "commit_dirty": commit_dirty == "true",
    "generated_at": timestamp,
    "config": {
        "target": target,
        "mode": mode,
        "workers": int(workers),
        "rate": float(rate),
        "max_pages": int(max_pages),
    },
    "runs": runs,
    "summary": summary,
    "non_deterministic_fields_observed": non_deterministic_fields,
    "notes": [
        "Metrics limited to fields verified present in scan_results.json; "
        "see docs/baselines/README.md for the full inspection record.",
        "max_pages, workers, rate and timeout are scan CONFIGURATION "
        "inputs, not scan OUTPUT — they are not echoed into "
        "scan_results.json and are recorded here from the invocation, "
        "not parsed from the report.",
    ],
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")

print(f"[baseline] wrote {out_path}")
PY

echo "[baseline] done."
