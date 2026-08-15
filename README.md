# Arfa VAPT Core v1

A Go-based authorized web vulnerability scanning core. This version stabilizes the scan pipeline before AI/Web3/Burp integrations.

## Pipeline
Crawler → Endpoint/Parameter model → detector-specific payloads → adaptive scheduler/rate limiter → HTTP probe → detector → deduplication → JSON/HTML report.

## Run
```bash
go build ./...
./arfa -target http://127.0.0.1:8080 -payload-dir ./payloads-database/PayloadsAllTheThings-master -mode quick -i-have-authorization
```

## Local test target
```bash
go run ./cmd/test-target
```
In another terminal, run Arfa against `http://127.0.0.1:8080` with the authorization flag.

Payloads are loaded only from the supplied PayloadsAllTheThings repository. No replacement payload database is bundled.


## Preflight reachability gate

Before active scanning, Arfa performs bounded DNS, TCP and HTTP/HTTPS checks. A target that cannot complete the baseline is reported as `inconclusive` and is not misreported as a clean scan. Use `-preflight-only` to test reachability without sending detector payloads, or `-skip-preflight` only when the target is known to be reachable.

Examples:

```bash
./arfa -target https://example.com -preflight-only -i-have-authorization
./arfa -target http://127.0.0.1:18080 -mode quick -workers 20 -rate 100 -i-have-authorization
```
