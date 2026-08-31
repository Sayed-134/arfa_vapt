#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
SERVER_PID=""
PYTHON_BIN="${PYTHON_BIN:-python3}"
export GOCACHE="${GOCACHE:-$TMPDIR/go-build-cache}"

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

on_error() {
  status=$?
  echo "===== E2E FAILURE ====="
  echo "exit_code=$status"
  echo "===== TEST TARGET LOG ====="
  cat "$TMPDIR/test-target.log" 2>/dev/null || true
  echo "===== LISTENING PORT 18080 ====="
  (ss -ltnp 2>/dev/null | grep ':18080' || true)
  exit "$status"
}
trap on_error ERR

cd "$ROOT"
go run ./cmd/test-target >"$TMPDIR/test-target.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do
  if curl --silent --fail http://127.0.0.1:18080/clean >/dev/null; then break; fi
  sleep 0.25
done
curl --silent --fail http://127.0.0.1:18080/clean >/dev/null

go run ./cmd/arfa \
  -target http://127.0.0.1:18080 \
  -payload-dir ./payloads-database/PayloadsAllTheThings-master \
  -mode quick -workers 20 -rate 100 -max-pages 30 \
  -out "$TMPDIR/go-report" -i-have-authorization

"$PYTHON_BIN" ai-engine/main.py \
  --input "$TMPDIR/go-report/scan_results.json" \
  --output "$TMPDIR/ai-report.json"

"$PYTHON_BIN" - "$TMPDIR/go-report/scan_results.json" "$TMPDIR/ai-report.json" <<'PY'
import json
import sys

go_result = json.load(open(sys.argv[1], encoding="utf-8"))
ai_result = json.load(open(sys.argv[2], encoding="utf-8"))

assert go_result["schema_version"] == "arfa.scan/v1"
assert go_result["scope"]["authorized"] is True
assert go_result["reachability"]["status"] == "reachable"
assert {f["category"] for f in go_result["findings"]} == {"SQLi", "XSS", "LFI"}
assert all(f["verification_status"] == "CONFIRMED" for f in go_result["findings"])
assert ai_result["metadata"]["input_findings_count"] == 3
assert ai_result["metadata"]["deduplicated_count"] == 3
assert ai_result["source_scan"]["schema_version"] == "arfa.scan/v1"
assert {f["category"] for f in ai_result["findings"]} == {"SQLi", "XSS", "LFI"}
PY
