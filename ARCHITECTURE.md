# Arfa Core v1 Architecture

## Runtime path

Target → Crawler → canonical Endpoint model → detector-specific payload scheduling → adaptive rate limiter → HTTP probe → detector → evidence check → deduplication → JSON/HTML/history.

The JSON boundary is a versioned `ScanEnvelope` (`schema_version: arfa.scan/v1`). The Go scanner emits scope/authorization, reachability, stats, and findings without replacing the original verification status. The Python engine preserves this envelope as `source_scan` in its final report.

## Design rules

- The supplied PayloadsAllTheThings repository is the source of truth; no replacement payload database is used.
- Quick and Standard modes are scheduling budgets only. Deep mode can exercise the full loaded repository.
- Each detector is matched only with its own payload category.
- Each endpoint parameter is isolated into its own scan job.
- HTTP status codes are preserved for detector logic; 403/429 change future pacing instead of silently deleting evidence.
- Findings carry evidence and a PoC request URL; confidence must not be treated as proof of exploitability.
- Active scanning requires explicit `-i-have-authorization` acknowledgement.
