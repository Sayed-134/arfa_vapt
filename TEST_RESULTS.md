# Arfa Core v2 Test Results

Environment used for validation: Go toolchain available in build environment.

## Static / unit validation

- `go test ./...` — PASS
- `go vet ./...` — PASS
- `go build ./...` — PASS
- Preflight package tests — PASS

## Deterministic local vulnerable fixture

Target: `http://127.0.0.1:18080`

Command used:
```bash
./arfa -target http://127.0.0.1:18080 -payload-dir ./payloads-database/PayloadsAllTheThings-master -mode quick -workers 20 -rate 100 -i-have-authorization
```

Result:
- Reachability: `reachable`
- Findings: `3`
- Requests: `980`
- Findings: SQLi (`id`), LFI (`file`), XSS (`q`)

## Preflight-only validation

The same local fixture returned:
- DNS: pass
- TCP: pass
- HTTP: pass
- Reachability: `reachable`
- Detector requests: `0`

## Remote timeout behavior

The preflight gate is designed to classify DNS/TCP/HTTP failures as `inconclusive` and stop the active scan instead of producing a false `No vulnerabilities found` result. A real remote target must be tested from the operator's network because reachability is environment-dependent.

The supplied PayloadsAllTheThings repository remains the payload source of truth; no replacement payload database was introduced.
