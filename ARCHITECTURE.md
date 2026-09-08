# ARFA VAPT — Complete Architecture

## 1. Project Overview

ARFA VAPT is an authorized Vulnerability Assessment and Penetration Testing platform combining a Go-based security scanning core with a Python AI Engine.

The platform is designed to support:

* Web2 applications
* APIs
* Web3 / Smart Contracts
* Future security integrations such as Burp Suite, Mobile Analysis, and additional security tooling

The architecture is developed incrementally through defined milestones and implementation phases.

The **latest agreed architecture is the authoritative architectural reference for development direction and phase boundaries**.

The actual source code remains the source of truth for what functionality is currently implemented.

Completed milestones represent existing functionality and must be preserved unless an explicit architectural change is approved.

Development must remain:

* Incremental
* Test-driven
* Modular
* Reviewable
* Reproducible
* Security-focused
* Backward-compatible
* Minimal in scope

Future architectural layers must not be implemented prematurely.

---

# 2. Core Foundation

## Go Core Scanner

The Go Core Scanner is the primary deterministic scanning and execution layer.

### Core Components

* CLI Interface
* Authorization / Scope Management
* Reachability Check
* Web Crawler
* Canonical Endpoint Model
* HTTP / Probe Engine
* Payload Engine
* Detector Engine

  * SQL Injection Detection
  * Cross-Site Scripting Detection
  * Local File Inclusion Detection
* Adaptive Controller
* Rate Limiting
* Error Classification
* Timeout / Cancellation
* Progress Reporting
* Graceful Shutdown
* Finding Model
* Deduplication / Fingerprinting
* JSON Reporting

The Go core remains the deterministic execution layer.

AI components must not silently replace deterministic scanning, established contracts, coverage tracking, or verification behavior.

---

# 3. Runtime Path and Data Contract

The established core runtime concept is:

```text
Target
  ↓
Crawler
  ↓
Canonical Endpoint Model
  ↓
Detector-Specific Payload Scheduling
  ↓
Adaptive Rate Limiter
  ↓
HTTP Probe
  ↓
Detector
  ↓
Evidence Check
  ↓
Deduplication / Fingerprinting
  ↓
Finding
  ↓
JSON Reporting
```

The JSON boundary between the Go scanner and downstream analysis is the versioned `ScanEnvelope`.

```text
schema_version: arfa.scan/v1
```

The Go scanner emits the scan envelope containing scope / authorization information, reachability information, statistics, and findings.

The original verification status of findings must be preserved.

The Python AI Engine consumes the Go scan result and preserves the original scan envelope as `source_scan` in its final analysis/report.

This data contract is part of the completed foundation and must remain backward-compatible.

---

# 4. Milestone 1 — Completed and Locked

Milestone 1 established the foundational scan contract and regression behavior.

## Completed Components

* `ScanEnvelope`
* Schema Version: `arfa.scan/v1`
* Scope Management
* Authorization Record
* Authorization Gate
* CLI Authorization Requirement
* `-i-have-authorization`
* Config Support
* `-config`
* Timeout Support
* `-timeout`
* Verification Status Model

## Verification Statuses

The system preserves verification states including:

* `CONFIRMED`
* `FALSE_POSITIVE`
* `INCONCLUSIVE`
* `LIKELY`

## Milestone 1 Rule

Milestone 1 is **completed and locked**.

Its contracts must not be casually modified, redesigned, or replaced.

Any future change affecting the Milestone 1 scan contract requires explicit architectural approval and regression validation.

---

# 5. Milestone 2 — Completed Locally

Milestone 2 extends the execution model with evidence, coverage, deterministic planning, and adaptive execution controls.

## Completed Components

* `ARFA_MASTER_CONTEXT.md`
* Coverage Model
* Endpoint × Parameter × Vulnerability Category tracking
* Coverage States
* Deterministic Planner
* Scanner Interfaces
* `MaxJobs` support
* Adaptive Budget
* `NextActions`
* `EvidenceDetail`
* Execution Evidence
* Coverage Tracking

## Coverage Model

Coverage is tracked across:

```text
Endpoint × Parameter × Vulnerability Category
```

Coverage states include:

* `NotAttempted`
* `Attempted`
* `Failed`
* `Inconclusive`
* `Verified`

Coverage tracking must remain deterministic and thread-safe.

## Planner

The planner is deterministic.

It produces `NextActions` from the current coverage state.

The planner is:

* Deterministic
* Reviewable
* Non-autonomous
* Not LLM-driven

The planner must not be replaced by an LLM or autonomous agent.

## Adaptive Execution

Milestone 2 introduced execution controls including:

* `MaxJobs`
* Adaptive budget
* Planned `NextActions`
* Execution evidence
* Coverage snapshots

The adaptive planning mechanism remains bounded and deterministic.

## Milestone 2 Status

Milestone 2 implementation and local regression are completed.

The following were validated locally:

* Go build
* Go tests
* Go vet
* Python AI Engine tests
* Local end-to-end execution

Historical CI/regression issues are treated separately from the Milestone 2 architecture and do not justify redesigning or weakening Milestone 1 or Milestone 2 contracts.

Any change to those contracts requires explicit approval.

---

# 6. Python AI Engine — Completed

The Python AI Engine consumes results produced by the Go scanning core.

## Responsibilities

* Go ScanResult → Python Analysis
* Parsing
* Correlation
* Finding Analysis
* Prioritization
* Reporting

The AI Engine must preserve the original scan data and established contracts.

The AI Engine is an analysis layer and must not silently alter authoritative scan facts.

Local regression includes:

```text
14 tests passed
```

---

# 7. Current Phase — Verification Data Flow

The current implementation phase is:

## Verification Data Flow

The target verification pipeline is:

```text
Detection
   ↓
Verification
   ↓
Evidence Collection
   ↓
False Positive Check
   ↓
Confidence Scoring
   ↓
Finding
   ↓
Final JSON Report
```

The purpose of this phase is to make findings more trustworthy, explainable, reproducible, and evidence-backed.

The Verification phase extends the existing scanner without replacing the completed Milestone 1 or Milestone 2 contracts.

Verification must remain transparent and deterministic wherever possible.

---

# 8. `pkg/verification` — Current Phase Scope

`pkg/verification` is the primary implementation area for the current Verification Data Flow phase.

The following capabilities define the target scope of this phase:

* Verification Status
* Verification Detail
* Verification Methods
* Evidence Collection
* False Positive Detection
* Verification Queue
* Bounded Retry Logic
* Parallel Verification
* Verification Result Cache
* Confidence Evaluation

These items describe the **current implementation scope/target**. Their presence in this architecture must not be interpreted as proof that every item is already implemented.

Before implementing or modifying any item, the actual current source code must be inspected and the existing behavior must be established.

---

# 9. Verification Evidence

Evidence must provide enough information to support and reproduce a finding without unnecessarily storing raw sensitive material.

Evidence should be:

* Structured
* Minimal
* Relevant
* Reproducible
* Safe to serialize
* Associated with the corresponding finding

Evidence must not become an uncontrolled storage mechanism for:

* Secrets
* Credentials
* Session tokens
* Unnecessary sensitive response data

Existing evidence contracts from completed milestones must be preserved.

---

# 10. False Positive Detection

Verification must explicitly support false-positive evaluation.

The intended flow is:

```text
Detection Signal
      ↓
Verification Attempt
      ↓
Evidence Evaluation
      ↓
False Positive Check
      ↓
Final Verification State
```

The system must not automatically mark every detector result as confirmed.

Verification should distinguish between detection signals and authoritative verification results.

---

# 11. Verification Queue and Retry Logic

Verification may require additional attempts.

The current phase therefore includes the design and implementation of:

* Verification Queue
* Bounded Retry Logic
* Parallel Verification
* Verification Result Caching

Retries must remain bounded and must respect:

* Timeouts
* Cancellation
* Rate Limits
* Execution Budgets
* Target Scope
* Authorization Constraints

Verification must not create uncontrolled request amplification.

Any concurrency introduced during verification must remain compatible with existing execution controls.

---

# 12. Confidence Scoring

Verification results may contribute to a confidence score.

Confidence scoring should be:

* Explainable
* Reproducible
* Based on available evidence
* Consistent across equivalent verification results

Confidence must not replace the authoritative verification status.

The system should retain both:

```text
Verification Status
+
Confidence Information
```

The exact scoring implementation must be derived from the actual source and current phase requirements rather than assumed from this architecture alone.

---

# 13. Integration with `pkg/report`

`pkg/report` integrates verified findings into the final reporting layer.

## Required Integration

The current Verification phase may require minimal integration for:

* Unified Finding Output
* Evidence Attachments
* Confidence Information
* Final JSON Report

## `pkg/report` Protection Rule

`pkg/report` is protected from unrelated refactoring or redesign.

During the Verification phase, changes to `pkg/report` are permitted **only when they are the minimum changes required to integrate Verification output**.

No unrelated reporting redesign is permitted during this phase.

---

# 14. Complete Current Verification Flow

The intended current implementation flow is:

```text
Detector
   ↓
Finding Candidate
   ↓
Verification Queue
   ↓
Verification Method
   ↓
Evidence Collection
   ↓
False Positive Evaluation
   ↓
Confidence Evaluation
   ↓
Verified Finding
   ↓
Unified Report Finding
   ↓
Final JSON Report
```

Existing Milestone 1 and Milestone 2 contracts remain intact throughout this process.

---

# 15. Future Architectural Layers

The following layers are planned for future phases.

They are architectural targets and are **not part of the current implementation phase**.

---

## 15.1 Continuous Recon Layer — CIScanner

Planned responsibilities include:

* Subdomain Monitoring
* HTTP Validation
* Periodic Vulnerability Scanning
* GitHub Actions Integration
* Discord Notifications

Possible workflow:

```text
.github/workflows/
├── subdomain-monitor.yaml
│   ├── Subfinder
│   ├── HTTPx Validation
│   └── Discord Notifications
│
└── vuln-scan.yaml
    ├── Subfinder + HTTPx
    ├── Nuclei Scanning
    └── Discord Reports
```

This layer is deferred until the current Verification phase is completed and approved for progression.

---

# 16. Agentic AI Layer — PentesterFlow

A future agentic layer may provide controlled penetration-testing workflows.

Planned structure:

```text
agent/pentesterflow/
├── agent.py
├── skills/
│   ├── web_vulns.py
│   ├── ssrf.py
│   ├── ssti.py
│   ├── jwt.py
│   ├── graphql.py
│   └── race.py
├── models/
│   └── ollama.py
└── burp_bridge.py
```

The future agentic layer must follow:

* Human-in-the-Loop
* Transparent Execution
* Operational Learning
* Explicit Authorization Boundaries
* Controlled Execution

Agentic functionality must not be introduced into the current deterministic scanner or planner prematurely.

---

# 17. Orchestration Layer

A future orchestration layer may connect the major components.

Planned structure:

```text
orchestrator/
├── trigger.py
├── webhook.py
└── config.yaml
```

Possible future workflow:

```text
CIScanner
    ↓
Orchestrator
    ↓
PentesterFlow
    ↓
ARFA Core
    ↓
Knowledge Base
    ↓
Dashboard
```

This layer is deferred.

---

# 18. Knowledge Base

A future SQLite-based Knowledge Base is planned.

Possible structure:

```text
knowledge/
├── migrations/
│   └── 001_init.sql
├── models/
│   ├── targets.go
│   ├── scans.go
│   └── findings.go
└── store.go
```

Possible tables:

```text
targets
scans
findings
knowledge_base
```

Planned responsibilities include:

* Historical Scan Storage
* Finding History
* Target History
* Knowledge Retrieval
* Learning Patterns

This layer must not be implemented prematurely.

---

# 19. Web Dashboard

A future Web Dashboard may provide visualization and management.

Possible structure:

```text
dashboard/
├── frontend/
│   ├── src/
│   │   ├── App.js
│   │   └── pages/
│   │       ├── Dashboard.js
│   │       └── ScanDetail.js
│   └── package.json
│
└── backend/
    ├── main.go
    └── handlers/
        ├── scans.go
        └── findings.go
```

Possible APIs:

```text
/api/scans
/api/findings
/api/stats
```

The Dashboard is a future layer and is not part of the current Verification implementation.

---

# 20. Optional Integrations

These integrations are architectural options and are deferred until their respective phases are approved.

## Burp Bridge

Potential future capabilities:

```text
Burp Suite Integration
- Hybrid Mode
- Local API Integration
- Extension Support
- Import / Export Results
```

## Web3 Scanner

Potential future capabilities:

* Solidity Parsing
* Slither Integration
* Mythril Integration
* Smart Contract Analysis

Potential vulnerability categories:

* Reentrancy
* Integer Overflow / Underflow
* Access Control
* Other Smart Contract Security Issues

## Mobile Scanner

Potential future capabilities:

* APK Analysis
* Endpoint Extraction
* API Discovery
* Certificate Analysis

---

# 21. Complete Future Platform Flow

The long-term platform architecture is:

```text
User Input
(URL / Contract / APK)
        ↓
Auto-Detector
        ├── Web Target
        │      ↓
        │   Core Scanner
        │
        ├── Smart Contract
        │      ↓
        │   Web3 Scanner
        │
        └── Mobile App
               ↓
           Mobile Scanner
        ↓
Scanning Engine
        ├── Recon
        ├── Detection
        └── AI Analysis
        ↓
Verification
        ├── Evidence Collection
        ├── False Positive Check
        └── Confidence Scoring
        ↓
Knowledge Base
        ├── Store Results
        ├── Historical Data
        └── Learning Patterns
        ↓
Reporting
        ├── PDF
        ├── HTML
        ├── JSON API
        └── Notifications
```

This represents the long-term architecture and must not be interpreted as a requirement to implement every layer immediately.

---

# 22. Development Priorities

Implementation is intentionally phased.

## Phase 1 — Verification Data Flow

**Current phase.**

Focus:

* Verification
* Evidence
* False Positive Detection
* Confidence
* Report Integration
* Regression Safety

## Phase 2 — CIScanner Integration

Future.

## Phase 3 — PentesterFlow Integration

Future.

## Phase 4 — Orchestrator

Future.

## Phase 5 — Knowledge Base

Future.

## Phase 6 — Web Dashboard

Future.

## Phase 7 — Burp Bridge

Optional.

## Phase 8 — Web3 Scanner

Optional.

Mobile capabilities may be introduced through a future dedicated phase when explicitly approved.

---

# 23. Core Engineering Principles

ARFA VAPT development follows these principles:

1. Human-in-the-Loop
2. Transparent Execution
3. Modular Design
4. Test-Driven Development
5. Continuous Integration
6. Plugin Architecture
7. API-First Approach
8. Backward Compatibility
9. Deterministic Core Behavior
10. Minimal and Reviewable Changes
11. Explicit Authorization Boundaries
12. Reproducible Results

---

# 24. Main Development Commands

## Build

```bash
go build ./...
```

## Test

```bash
go test ./...
```

## Vet

```bash
go vet ./...
```

## Run Authorized Local Target

```bash
./arfa \
  -target "http://127.0.0.1:18080" \
  -mode quick \
  -workers 20 \
  -rate 100 \
  -i-have-authorization
```

## Verbose Mode

```bash
./arfa \
  -target "URL" \
  -mode deep \
  -verbose \
  -i-have-authorization
```

---

# 25. Protected Components

The following components are considered protected and must not be modified unnecessarily:

```text
pkg/crawler
pkg/detectors
pkg/scanner
pkg/payloads
pkg/httpclient
pkg/ratelimiter
cmd/arfa
cmd/test-target
go.mod
go.sum
```

These components should only be modified when:

* The current phase explicitly requires it
* The change is technically necessary
* The reason is documented
* Regression tests are provided
* Backward compatibility is preserved where applicable

## Special Rule: `pkg/report`

`pkg/report` is also protected from unrelated changes.

However, the current Verification phase explicitly allows the **minimum required integration changes** in `pkg/report` for:

* Verified findings
* Evidence attachments
* Confidence information
* Final JSON output

No unrelated refactor or redesign is permitted.

---

# 26. Phase Discipline

Development must follow strict phase discipline.

## Do Not

* Rewrite Milestone 1
* Redesign Milestone 2
* Break existing scan contracts
* Modify locked components without justification
* Implement future architectural layers prematurely
* Replace deterministic planning with an LLM
* Introduce autonomous behavior into the current core
* Perform unrelated refactoring
* Expand the scope of the current phase unnecessarily

## Do

* Inspect the actual current source code before implementation
* Confirm that documented functionality actually exists
* Identify the exact files that need modification
* Keep changes minimal
* Use dedicated feature branches
* Add or update tests with implementation
* Run appropriate validation
* Preserve backward compatibility
* Review diffs before committing
* Keep changes reversible and reviewable
* Maintain transparent execution

---

# 27. Source-of-Truth Rules

When architectural documentation, milestone documentation, and source code differ:

1. The Final Architecture defines the intended architectural direction and phase boundaries.
2. The actual source code defines what is currently implemented.
3. Completed milestone contracts must be preserved.
4. Documentation must not be treated as proof that functionality exists.
5. Implementation proposals must first inspect the actual source.
6. Any intentional architectural change must be explicitly approved.

The system must never assume that a future component exists simply because it is listed in this architecture.

---

# 28. Testing and Regression Requirements

Every implementation phase must include appropriate validation.

At minimum, changes should be evaluated using the relevant combination of:

```text
go build ./...
go test ./...
go vet ./...
Python test suite
End-to-End regression
```

Where applicable, Verification changes must also validate:

* Existing Milestone 1 behavior
* Existing Milestone 2 behavior
* ScanEnvelope compatibility
* Finding compatibility
* Verification status preservation
* JSON output compatibility

A feature is not considered complete merely because it compiles.

---

# 29. Security and Authorization Requirements

ARFA VAPT is an authorized security assessment platform.

All scanning and verification execution must remain bounded by:

* Explicit authorization
* Defined target scope
* Rate limits
* Execution budgets
* Timeouts
* Cancellation
* Safe error handling

The architecture must favor controlled, transparent, auditable execution.

---

# 30. Current Implementation Boundary

At the current stage, the implementation focus is strictly:

```text
Existing Go Core
       ↓
Existing Detection
       ↓
Verification
       ↓
Evidence
       ↓
False Positive Evaluation
       ↓
Confidence
       ↓
Finding
       ↓
Final JSON Report
```

The following are **not current implementation requirements**:

```text
CIScanner
PentesterFlow
Orchestrator
Knowledge Base
Dashboard
Burp Bridge
Web3 Scanner
Mobile Scanner
```

They remain future architectural layers.

---

# 31. Final Architectural Rule

This document is the authoritative architectural reference for ARFA VAPT development direction and phase discipline.

The actual source code remains the source of truth for implemented functionality.

The project must evolve incrementally from the existing verified foundation.

Completed milestones remain stable.

The current phase must be completed before progressing to future layers.

Every change must be:

* Necessary
* Minimal
* Testable
* Reviewable
* Reproducible
* Secure
* Compatible with existing contracts

**ARFA VAPT must grow by extending the verified foundation, not by repeatedly rewriting it.**
