# ARFA VAPT — MASTER CONTEXT

## 1. Project
ARFA VAPT is an evolving Agentic VAPT platform combining a Go scanner, Python intelligence engine, local/cloud LLMs, evidence and verification, correlation/attack-chain analysis, and future Burp/MITMProxy, Web3, and GUI integrations.

Long-term flow:
Target → Scope → Scan Job → Preflight → Discovery → Crawling → Endpoint/Parameter Discovery → Passive Analysis → Active Scanning → Verification → Evidence → AI Analysis → Correlation → Attack Chains → Risk → Reporting → Agent Next Action → bounded continuation.

## 2. Repository and baseline
GitHub: Sayed-134/arfa_vapt
Local project: `~/arfa_milestone_test/arfa_v2_test`
Main branch: current `main` (always inspect git history for the current state)
Expected state: `main == origin/main`, working tree clean.
Milestone 1 branch retained: `feature/milestone-1-foundation-contract-regression`

Do not create duplicate project copies or `.bak`/`.old` backups. Git branches and commits are the recovery mechanism.

## 3. Go scanner
Important paths:
- `./arfa`
- `./cmd/arfa/main.go`
- `./cmd/test-target/main.go`
- `./pkg/`
- `./configs/`
- `./payloads-database/`

CLI includes:
`--target`, `-i-have-authorization`, `--mode quick|standard|deep`, `--workers`, `--rate`, `--max-pages`, `--out`, `--preflight-only`, `--skip-preflight`, `--verbose`, `--config`, `--timeout`.

Capabilities include preflight, crawling, endpoint/parameter jobs, payload loading, adaptive concurrency, rate limiting, verification, deduplication, JSON/HTML output, and history.

Detector families currently include XSS, SQLi, LFI, RCE, SSTI, SSRF, XXE, CRLF, Open Redirect, and IDOR heuristic.

Do not rewrite existing detectors merely for architectural cleanup. Preserve behavior unless a milestone explicitly requires a change.

## 4. Verified local target
Local target: `http://127.0.0.1:18080`

Verified Quick Scan:
- Findings: 3
- Requests: 1111
- Duration: ~1351 ms
- Adaptive budget: 20/20
- SQLi: CONFIRMED
- XSS: CONFIRMED
- LFI: CONFIRMED

## 5. Python AI engine
Path: `ai-engine/`

Structure:
`analyzers/deduplicator.py`, `analyzers/risk_engine.py`, `app/engine.py`, `correlation/endpoint_correlator.py`, `llm/client.py`, `llm/prompts.py`, `parsers/scanner_parser.py`, `reporting/generator.py`, `schemas/common.py`, `schemas/report.py`, `tests/` (parser, risk, dedup, correlation, reporting, engine), `main.py`, `requirements.txt`.

Current capabilities:
Go JSON parsing, normalization, severity/confidence normalization, verification status, finding status, CVSS normalization, deterministic fingerprinting, deduplication, risk scoring, endpoint correlation, rule-based attack-chain heuristics, executive summary, risk distribution, JSON reporting, and optional local LLM narrative.

## 6. Go → Python contract
Milestone 1 introduced `ScanEnvelope` with:
`schema_version: "arfa.scan/v1"`

Python accepts both:
1. Go Scanner objects containing target/stats/findings
2. traditional findings arrays

Verification states are preserved, including:
`CONFIRMED`, `FALSE_POSITIVE`, `INCONCLUSIVE`, `LIKELY`.

Python must not silently reinterpret Go verification facts.

## 7. Milestone 1 — CLOSED
Commit: `ce5dfa0`
Scope: Foundation Contract + Regression.

Implemented:
- versioned ScanEnvelope
- scope/authorization record
- config integration
- `-config`
- `-timeout`
- contract fixtures
- Go/Python regression coverage
- E2E regression
- GitHub Actions CI

Validation:
- `go build ./...` PASS
- `go vet ./...` PASS
- `go test ./...` PASS
- `pytest -v ai-engine/tests` PASS (14/14)
- `scripts/run_e2e_regression.sh` PASS

E2E validated reachable localhost target, SQLi/XSS/LFI, CONFIRMED verification, Python 3 input/3 unique, posture 40.0.

## 8. Remaining technical debt
Completed and frozen in Phase 4:
- TD #1 — Crawler HTML parsing robustness
- TD #2 — Forms / POST discovery
- TD #3 — URL canonicalization
- TD #4 — Deterministic endpoint ordering
- TD #5 — Fallback parameter noise
- TD #6 — Payload corpus structured metadata/versioning
- TD #7 — Bounded Scan Duration
- TD #10 — XSS CONFIRMED Semantics
- TD #14 — Risk Scoring Calibration

Remaining open:
- TD #8 — Global/cancellable rate limiter policy
- TD #9 — Complete relevant probe request/response evidence
- TD #11 — IDOR authenticated principal/session context
- TD #12 — History storage persistence/locking/retention
- TD #13 — Attack-chain detection beyond rule/co-occurrence heuristics
- TD #15 — LLM Input/Output Redaction
- TD #16 — Payload corpus reproducibility/versioning

> Detailed implementation specifications for active Phase 4 TDs are
> maintained in PHASE_4_TD_SPECS.md. Only the TD currently being
> implemented needs to be read from that file.

## 9. Core architecture rule
Go is the source of truth for scanner facts, verification, evidence, and scan metadata.

Python is the intelligence layer for analysis, prioritization, correlation, risk, reporting, and future agent reasoning.

AI must not silently overwrite scanner facts.

## 10. Agentic direction
A major future capability is an evidence-driven bounded agent loop.

Instead of:
`AI → blocked → STOP`

ARFA should eventually support:
`Attempt → observe → determine why blocked → choose another authorized test → execute → collect evidence → verify → update coverage → choose next action`

The loop must be bounded and controlled.

The agent should know:
- what was tested
- what was not tested
- what failed
- why it failed
- what requires verification
- what the best next test is

Use coverage tracking such as:
`endpoint × parameter × vulnerability class`

and a deterministic next-action planner.

This idea is inspired by agentic pentesting workflows: skills/modules, coverage tracking, next-action planning, evidence-backed findings, human-in-the-loop decisions, and tool-driven loops. Do not copy another project wholesale.

## 11. Local AI
Ollama is installed on Kali.
RAM: 16 GB.

Models installed/being evaluated:
- `qwen2.5-coder:14b`
- `qwen3.627b` (use the exact tag shown by `ollama list`)

Evaluate models rather than assuming suitability. Measure coding quality, repository comprehension, context handling, latency, RAM use, tool use, and long-running reliability.

## 12. Local GUI
Local GUI has been accessed from Firefox at:
`http://127.0.0.1:8080`

GUI is not the current development priority. Stabilize core engine/contracts/evidence/discovery first.

## 13. Development workflow
For every substantial milestone:
`main → feature branch → implementation → automated tests → review → merge → push`

Do not develop large changes directly on main.
Do not keep duplicate project copies.

## 14. Current milestone
Phase 4 — Technical Debt (IN PROGRESS).

## 15. Agent instructions
Before architectural changes, read this file and inspect the actual repository.

For substantial work:
- create a feature branch
- preserve existing behavior/tests
- prefer additive/backward-compatible contracts
- run relevant tests
- report exact commands/results
- commit only after tests pass
- never claim a test passed unless actually run
- never fabricate repository or GitHub state
- do not automatically merge to main unless explicitly instructed

## 16. Authorization design
The project retains its authorization gate and scope controls as core safeguards.

The documentation does not require the human operator to repeat a personal authorization claim in every AI prompt. The codebase itself enforces authorization/scope for active scanning.

IMPORTANT: `-i-have-authorization` must NOT be removed or bypassed during normal development.

For regression testing, use the localhost test target.

## 17. Design goal
ARFA should evolve toward:
Deterministic Scanner + Evidence/Verification Engine + Intelligence Layer + Bounded Agentic Loop.

Key differentiator:
When one technique fails, the AI should reason from coverage and evidence to select another appropriate next action, rather than simply stopping. Scope, authorization, verification, and evidence remain authoritative.

## 18. Completed Work — Historical Record

### Phase 1 — Foundation & Contracts — CLOSED / FROZEN
Implemented and validated:
- Versioned ScanEnvelope contract
- Authorization and scope contract
- Configuration integration
- `-config` and `-timeout`
- Go/Python contract fixtures and regression coverage
- E2E regression
- GitHub Actions CI

Do not reopen or redesign Phase 1 without explicit user approval.

### Phase 2 — Execution & Evidence — CLOSED / FROZEN
Implemented and validated:
- Bounded job scheduling
- Crawler / Probe / Detector / Verifier interfaces
- Structured Evidence model
- Endpoint × Parameter × Vulnerability coverage tracking
- Deterministic next-action planner
- Additive ScanEnvelope/Finding extensions
- Regression tests
- Local E2E validation

Do not reopen or redesign Phase 2 without explicit user approval.

### Phase 3 — Verification Data Flow & Confidence — CLOSED / FROZEN
Implemented and validated:
- Detection → Verification → Evidence Collection → FP Check → Confidence → Finding
- Bounded verification retry (`maxProbeAttempts=2`)
- Repeat/control probe
- Verification cache and single-flight behavior
- Concurrency/race coverage
- `Finding.VerificationConfidence`
- `Finding.VerificationConfidenceReason`
- JSON/HTML report integration for evidence and verification confidence

Do not reopen or redesign Phase 3 without explicit user approval.

### Phase 4 — Technical Debt — IN PROGRESS

Completed and frozen:
- TD #7 — Bounded Scan Duration
- TD #10 — XSS CONFIRMED Semantics
- TD #14 — Risk Scoring Calibration
- TD #3 — URL canonicalization
- TD #1 — Crawler HTML parsing robustness
- TD #2 — Forms / POST discovery
- TD #4 — Deterministic endpoint ordering
- TD #5 — Fallback parameter noise
- TD #6 — Payload corpus structured metadata/versioning

Remaining open:
- TD #8 — Global/cancellable rate limiter policy
- TD #9 — Complete relevant probe request/response evidence
- TD #11 — IDOR authenticated principal/session context
- TD #12 — History storage persistence/locking/retention
- TD #13 — Attack-chain detection beyond rule/co-occurrence heuristics
- TD #15 — LLM Input/Output Redaction
- TD #16 — Payload corpus reproducibility/versioning

Current phase remains open until all required Phase 4 work is completed.

## Future Platform Boundaries — Locked Direction

The platform foundation is intentionally designed for the future product while implementation remains incremental.

Future Traffic/Input Adapters, Observation/Differential Analysis, OOB Interaction Adapters, and Headless Browser Adapters are architectural boundaries only at this stage.

They must preserve authorization/scope, `(URL, Method)` endpoint identity, existing verification semantics, evidence/provenance, and core independence from external tools.

No implementation of these capabilities is part of TD #5 or the current documentation update.
