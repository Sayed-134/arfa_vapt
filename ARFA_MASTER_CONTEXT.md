# ARFA VAPT — MASTER CONTEXT

> **Current operational reference.** This document records the verified project state, implementation contracts, closed work, development rules, and the current phase boundary. It is not a replacement for `ARCHITECTURE.md` or `PLATFORM_STRATEGY.md`.

---

## 1. Project Identity

ARFA VAPT is an authorized security assessment and security-intelligence platform.

The current verified foundation is a deterministic Go-based Web2/API assessment core with a Python intelligence layer. The long-term platform is designed to expand into browser/traffic assessment, mobile, Web3, external attack-surface discovery, OAST, race testing, external-tool integration, plugins, AI-assisted correlation and bounded agentic workflows, reporting, history, and continuous assessment.

The platform is intended to grow without sacrificing:

- authorization and scope enforcement;
- deterministic scanner truth;
- verification authority;
- evidence and provenance;
- compatibility of stable contracts;
- reproducibility and auditability;
- bounded execution and recovery;
- human control over elevated or destructive operations.

The complete architectural destination is defined in `ARCHITECTURE.md`. Long-term strategy and capability intake are defined in `PLATFORM_STRATEGY.md`.

---

## 2. Source of Truth

Use the following hierarchy:

1. **Actual repository source code** — authoritative for implemented behavior.
2. **`ARFA_MASTER_CONTEXT.md`** — authoritative for current project state, closed work, active phase, and operational rules.
3. **`ARCHITECTURE.md`** — authoritative for long-term architectural direction and boundaries.
4. **`PLATFORM_STRATEGY.md`** — authoritative for long-term strategy, intake, and ecosystem direction.
5. Other specifications are subordinate references for their defined scope.

If documentation says a capability exists but the repository does not verify it, treat the capability as **not implemented**.

If implementation requires behavior that conflicts with the architecture, stop at the architectural boundary and resolve the conflict explicitly before implementation.

---

## 3. Repository and Working Rules

Repository:

- GitHub: `Sayed-134/arfa_vapt`
- Main development branch: `main`
- Current implementation must be inspected before substantial changes.

Working rules:

- Do not create duplicate project copies.
- Do not create `.bak`, `.old`, or recovery copies.
- Git branches and commits are the recovery mechanism.
- Closed work is frozen unless an explicit architectural decision authorizes evolution.
- Prefer additive and backward-compatible changes.
- Make the smallest necessary change.
- Do not refactor unrelated code during a scoped implementation.
- Do not invent repository files, interfaces, capabilities, or test results.
- Do not claim a capability is implemented without repository evidence.

---

## 4. Current Platform Boundary

The current implementation foundation remains the deterministic Go scanner plus the Python intelligence engine.

Conceptual long-term flow:

```text
Target
  ↓
Scope / Authorization
  ↓
Assessment / Run
  ↓
Preflight / Readiness
  ↓
Discovery / Attack Surface
  ↓
Execution
  ↓
Observation
  ↓
Verification
  ↓
Evidence
  ↓
Finding
  ↓
AI Analysis / Correlation
  ↓
Attack Chains / Risk
  ↓
Reporting
  ↓
Bounded Next Action / Continuation
```

This flow describes the platform direction. It does not mean every stage is currently implemented as a separate subsystem.

---

## 5. Go Core — Current Source of Security Truth

Go remains the deterministic execution and security-truth layer.

It owns, subject to the current repository implementation:

- authorization and scope gates;
- target handling and preflight;
- crawling/discovery;
- endpoint and parameter handling;
- payload scheduling/loading;
- detector execution;
- rate limiting and bounded execution;
- verification;
- evidence collection;
- finding status;
- coverage/execution state;
- scan metadata and statistics;
- deterministic reporting/history integration.

AI must not silently overwrite scanner facts, verification status, evidence, or authorization state.

---

## 6. Python Intelligence Layer

`ai-engine/` is the intelligence layer.

Its role includes analysis, normalization, deduplication, risk, correlation, attack-chain reasoning, reporting, and optional LLM-assisted narrative/reasoning.

Python may interpret and enrich scanner output, but it must preserve authoritative Go facts and provenance.

The intelligence layer must never:

- bypass authorization;
- create an authoritative finding without the required evidence/verification path;
- silently change scanner verification status;
- treat an AI hypothesis as a verified vulnerability;
- use external knowledge as a substitute for target evidence.

---

## 7. Stable Scan Contract

The established Go → downstream contract uses:

```text
schema_version: arfa.scan/v1
```

`ScanEnvelope` is a compatibility boundary from the completed foundation.

The existing verification statuses remain authoritative:

- `CONFIRMED`
- `FALSE_POSITIVE`
- `INCONCLUSIVE`
- `LIKELY`

Future architecture must remain readable and compatible with `arfa.scan/v1`. New platform concepts should prefer additive, composable records/contracts rather than casually replacing the envelope with an incompatible universal schema.

---

## 8. Current Finding Truth Path

The platform follows this security-truth principle:

```text
Observation
    ↓
Candidate / Hypothesis
    ↓
Bounded Execution
    ↓
Verification
    ↓
Evidence
    ↓
Finding
```

External tools, AI, knowledge sources, traffic observations, browser observations, and differential signals are inputs/signals until they pass the appropriate normalization and verification boundaries.

A finding must remain traceable to the observations, execution, verification, and evidence supporting it.

---

## 9. Coverage and Readiness

Coverage and readiness are separate concepts.

### Readiness

Readiness answers:

> Can the target be meaningfully assessed with the capabilities and conditions available?

Transport reachability does not prove application assessability.

Examples of material readiness limitations include:

- authentication/session barriers;
- anti-bot or challenge pages;
- unsupported application behavior;
- broken session state;
- inaccessible application content;
- capability or protocol limitations.

### Coverage

Coverage answers:

> Which test obligations were attempted, failed, completed, or remain untested?

The long-term architecture uses **Test Obligations + Outcomes** as the source model, with matrices treated as projections.

A clean result must never imply complete security coverage when readiness or coverage is materially incomplete.

---

## 10. Authorization and Safety

ARFA is an authorized assessment platform.

The authorization gate is a core safeguard.

The CLI authorization requirement:

```text
-i-have-authorization
```

must not be removed or bypassed during normal development.

Every future execution boundary must preserve:

- authorization;
- scope;
- capability policy;
- egress restrictions;
- execution budgets;
- rate/time limits;
- approval requirements for elevated or destructive operations.

For regression testing, use the repository's localhost test target rather than an uncontrolled external target.

---

## 11. Protected Foundation

Unless a scheduled phase explicitly requires evolution, do not modify the closed foundation casually.

Protected areas include:

- `pkg/crawler`
- `pkg/detectors`
- `pkg/scanner`
- `pkg/payloads`
- `pkg/httpclient`
- `pkg/ratelimiter`
- `cmd/arfa`
- `cmd/test-target`
- `go.mod`
- `go.sum`

`pkg/report` should receive only the minimum integration necessary for an approved scope.

Protection does not mean permanent immutability. If the architecture or a future capability genuinely requires evolution, record the reason, define compatibility impact, and make the smallest justified change.

---

## 12. Completed Phase 1 — CLOSED / FROZEN

Foundation & Contracts established:

- `ScanEnvelope`
- `schema_version: arfa.scan/v1`
- scope/authorization record
- authorization gate
- `-i-have-authorization`
- `-config`
- `-timeout`
- verification status model
- Go/Python contract fixtures and regression coverage
- E2E regression
- CI integration

Commit:

```text
ce5dfa0
```

Phase 1 is closed and must not be redesigned without explicit approval.

---

## 13. Completed Phase 2 — CLOSED / FROZEN

Execution & Evidence established:

- bounded job scheduling;
- Endpoint × Parameter × Category coverage state;
- `NotAttempted` / `Attempted` / `Failed` / `Inconclusive` / `Verified` states;
- deterministic planner / next actions;
- `MaxJobs`;
- adaptive budget;
- structured evidence detail;
- minimal report integration.

Commit:

```text
bf9de2b
```

Phase 2 is closed and must not be redesigned without explicit approval.

---

## 14. Completed Phase 3 — CLOSED / FROZEN

Verification Data Flow & Confidence established:

- bounded verification attempts (`maxProbeAttempts=2`);
- control probe;
- evidence-strength confidence;
- authoritative finding status remains separate from confidence;
- verification cache with `GetOrCompute` / single-flight behavior;
- `VerificationConfidence` and reason;
- report evidence/confidence integration.

Relevant history includes:

```text
e995d6a
8c24a42
f27fa61
```

Phase 3 is closed and must not be redesigned without explicit approval.

---

## 15. Completed Phase 4 — CLOSED / FROZEN

Phase 4 technical debt is complete.

Completed TDs include:

- TD #1 — Crawler HTML parsing robustness
- TD #2 — Forms / POST discovery
- TD #3 — URL canonicalization
- TD #4 — Deterministic endpoint ordering
- TD #5 — Fallback parameter noise
- TD #6 — Payload corpus structured metadata/versioning
- TD #7 — Bounded Scan Duration
- TD #8 — Global/cancellable rate limiter policy
- TD #9 — Complete relevant probe request/response evidence
- TD #10 — XSS CONFIRMED Semantics
- TD #11 — IDOR authenticated principal/session context
- TD #12 — History storage persistence/locking/retention
- TD #13 — Evidence-backed attack-chain detection
- TD #14 — Risk Scoring Calibration
- TD #15 — LLM Input/Output Redaction
- TD #16 — Payload corpus reproducibility/versioning
- TD #17 — Method-aware parameter selection in detectors

Recorded implementation commits for the later TDs include:

- TD #11: `1da9cb7`
- TD #12: `10c4e50`
- TD #13: `f0b679d`
- TD #15: `c3f07b9`

Phase 4 is closed/frozen. Do not reopen or redesign it unless the user explicitly approves an architectural change.

---

## 16. TD #11 — Current Contract

TD #11 added authenticated principal/session context for IDOR-related testing.

Relevant concepts include:

- `AuthPrincipal`
- `AuthContext`
- `NewAuthContext`
- `Finding.AuthContext`
- explicit authentication/probe context
- cross-principal IDOR testing

Cross-principal evidence may produce `LIKELY`; it does not automatically become `CONFIRMED` without the required verification semantics.

Raw authentication context/secrets are not intended to be serialized into normal findings.

Future identity/session management must integrate with this contract rather than casually replacing it.

---

## 17. TD #12 — Current History Contract

History persistence is implemented in the existing `pkg/db` boundary.

The implementation supports, subject to repository verification:

- `Open(path string, opts ...Option)`;
- configurable retention;
- bounded record count;
- age-based retention;
- record IDs and timestamps;
- compatibility with legacy stored scan-result representation;
- locking for concurrent writers;
- atomic file replacement;
- parent-directory creation;
- errors returned to callers without requiring the scan itself to fail.

Do not replace this with a new persistence subsystem merely because a future architecture could use a database. Storage technology is an implementation decision driven by actual scale and requirements.

---

## 18. TD #13 — Current Attack-Chain Contract

Attack-chain support remains evidence-backed and deterministic at its authoritative boundary.

Python `AttackChain` was extended with:

- `relationships`
- `evidence_refs`

The existing `arfa.scan/v1` contract remains unchanged.

AI/correlation may propose relationships or hypotheses, but authoritative attack-chain conclusions must remain traceable to supporting evidence and must not become free-form LLM assertions.

---

## 19. TD #15 — Redaction

LLM input/output redaction is closed.

Redaction is a security boundary, not merely presentation formatting.

Secrets and sensitive material must not be unnecessarily exposed to LLMs, findings, reports, history, or normal evidence.

Future vault/identity/traffic/browser capabilities must preserve this boundary.

---

## 20. Current Phase Status

**Phase 4 is CLOSED / FROZEN.**

**The next implementation phase has not yet been formally opened.**

The next phase must be derived from the finalized architecture and strategy through capability/dependency analysis. It must not be chosen merely because a particular feature is attractive or familiar.

Before implementation begins, define:

1. capability objective;
2. architectural fit;
3. dependencies;
4. current implementation gap;
5. user workflow impact;
6. security boundaries;
7. evidence/provenance impact;
8. compatibility impact;
9. exact phase scope;
10. validation criteria.

---

## 21. Future Platform Direction — Locked Architectural Boundaries

The following are architectural directions, not claims of current implementation:

- Control Plane + constrained execution agents;
- Assessment / Run model;
- action identity, idempotency, cancellation, retry, and recovery;
- scope + authorization + capability + egress enforcement at every execution boundary;
- first-class identity/session/vault boundaries;
- first-class traffic/interception subsystem;
- first-class internal Browser assessment engine;
- native Mobile execution engine;
- native Web3 execution engine;
- OAST with isolated, expiring, correlated interactions;
- race/concurrency execution patterns;
- external security-tool integrations;
- controlled extension/plugin system;
- evidence custody and provenance;
- readiness separate from coverage;
- asset/attack-surface model;
- historical/regression/continuous assessment;
- bounded agentic continuation;
- AI/knowledge as intelligence, never authoritative security truth.

These capabilities are not automatically scheduled for the next phase.

---

## 22. Traffic and Browser Direction

Traffic is a core platform capability, not a side integration.

The architectural target includes:

- HTTP/HTTPS interception;
- request/response inspection;
- traffic history;
- application/site mapping;
- repeater-style workflows;
- intruder-style controlled iteration;
- authentication/session context;
- WebSocket/SSE/GraphQL-aware handling where applicable;
- traffic ↔ scanner interoperability;
- traffic ↔ findings/evidence linkage.

The internal Browser is also a first-class assessment engine and may support:

- JavaScript execution;
- SPA/dynamic discovery;
- browser state/session handling;
- DOM/network observations;
- browser-assisted verification;
- screenshots/visual evidence where justified;
- integration with traffic.

Implementation technology for these capabilities remains benchmark- and requirement-driven.

---

## 23. Mobile and Web3 Direction

Mobile is a domain-native capability, not an HTTP-only extension.

The future platform should support appropriate Android/iOS artifact, runtime, network, and behavioral assessment with common authorization, evidence, provenance, and reporting contracts.

Web3 is likewise domain-native and should cover, where applicable:

- smart contracts;
- ABI/interfaces;
- transaction behavior;
- wallets/signing boundaries;
- dApps;
- RPC interactions;
- chain/deployment metadata;
- authorization and business-logic analysis;
- simulation/trace/state-diff evidence.

Neither domain should be forced into an HTTP-only scanner model.

---

## 24. External Inputs and Tools

External tools and traffic sources are adapter inputs, not automatic sources of truth.

Examples include:

- Burp Suite;
- ZAP;
- Nuclei;
- mitmproxy;
- HAR/request-response artifacts;
- external reconnaissance sources;
- OAST providers.

Their observations/signals must be normalized at explicit boundaries and remain subject to ARFA authorization, scope, provenance, and verification rules.

Integration may be bidirectional where justified. The architecture does not reject a tool merely because it overlaps with ARFA.

---

## 25. AI, Knowledge, and Agentic Rules

AI may:

- analyze observations;
- correlate findings;
- prioritize work;
- generate hypotheses;
- propose next actions;
- reason over coverage;
- assist reporting;
- assist attack-chain analysis.

AI may not:

- bypass authorization/scope;
- bypass execution budgets or approval boundaries;
- silently change authoritative scanner facts;
- manufacture verified findings;
- convert unsupported hypotheses into confirmed vulnerabilities;
- suppress material limitations to make a report look cleaner.

Future agentic execution must be bounded by scope, capability, time, rate, budget, approval, and recovery rules.

---

## 26. Development Workflow

For a new implementation phase / TD:

```text
Current main / Source of Truth
        ↓
Confirm architecture + current state
        ↓
Define exact phase scope
        ↓
Implementation branch
        ↓
Claude / Codex / Gemini implementation
        ↓
Patch review
        ↓
Local validation
        ↓
Commit
        ↓
Push / PR / merge
        ↓
Freeze and record state
```

AI implementers must not merge to `main` without explicit instruction.

The user applies/reviews patches locally and controls Git integration.

---

## 27. Standard Patch Acceptance and Validation

For a returned patch:

```bash
git apply --check <patch>
git apply <patch>
git status
git diff --stat
git diff --check
git diff
gofmt -w <changed-go-files>
go build ./...
go vet ./...
go test ./...
```

For concurrency-sensitive changes, including cache/history/concurrent execution:

```bash
go test ./... -race
```

Run relevant Python tests for Python changes.

For cross-subsystem capabilities, perform an appropriate end-to-end validation.

Do not trust an implementation assistant's claim that tests passed until the local validation is actually run.

---

## 28. Phase / TD Prompt Rules

Implementation prompts must be short and scoped.

Standard structure:

```text
TD #X — [TD title]

Context: authorized VAPT platform covering Web2 + Web3 + Mobile, with a high-quality scalable architecture.

Source: read only the named section of [SPEC_DOC] plus the needed source files in Sayed-134/arfa_vapt.

Execution: follow the spec exactly; smallest scope; no behavior outside this TD; no edits/deletes unless required; do not touch closed work without asking; no out-of-scope components.

Delivery: return patch + short summary + files changed + tests run + concerns.
```

Do not expand the prompt with unrelated architecture or future capabilities unless the current TD requires them.

---

## 29. Documentation Roles

### `ARCHITECTURE.md`

Defines the complete platform architecture, stable boundaries, major architectural decisions, and the destination the implementation phases must follow.

### `PLATFORM_STRATEGY.md`

Defines long-term strategy, capability intake, extension/integration philosophy, ecosystem direction, decision discipline, and roadmap principles.

### `ARFA_MASTER_CONTEXT.md`

Defines current operational state, closed milestones, implementation contracts, protected foundation, current phase status, and rules for implementation work.

### `PHASE_4_TD_SPECS.md`

Historical/phase-specific reference for Phase 4 technical debt. Closed Phase 4 work is not reopened merely because this document still exists.

---

## 30. Documentation Consistency Rule

The three primary documents must not contradict each other.

The expected relationship is:

```text
ARCHITECTURE
    ↓ defines destination and boundaries
PLATFORM_STRATEGY
    ↓ defines strategy and intake
MASTER_CONTEXT
    ↓ records current verified state
SOURCE CODE
    ↓ proves what is actually implemented
```

A future capability appearing in Architecture or Strategy is not evidence that it exists in code.

A current implementation appearing in code does not automatically make it part of the long-term architecture; it must fit the documented boundaries or trigger an explicit architectural decision.

---

## 31. Current Baseline / Field-Test Lesson

An authorized external test against a challenge-protected target demonstrated an important product requirement:

```text
Transport reachable
        ≠
Application assessable
        ≠
Meaningful coverage
        ≠
No vulnerabilities
```

A target can respond successfully while presenting an anti-bot/challenge layer that prevents meaningful application assessment.

ARFA therefore needs first-class readiness/application-accessibility semantics in its future reporting and workflow. This is an architectural requirement, not a justification to bypass a target's defensive controls.

---

## 32. Local Environment Notes

Local AI evaluation has used Ollama on Kali. Model availability and exact tags are environment state and must be checked with the local installation before relying on them.

A local GUI has previously been reachable at:

```text
http://127.0.0.1:8080
```

GUI availability is an environment fact, not proof that the future platform GUI is implemented.

---

## 33. Current Decision Boundary

The documentation update establishes the architectural destination before selecting the next implementation phase.

The next phase should therefore be chosen only after a capability-gap/dependency review of the finalized three documents and the actual repository.

Possible future work must be evaluated against the full platform, including the user workflow and dependency chain, rather than selected as an isolated feature.

No next phase is considered open until its scope is explicitly approved.

---

## 34. Final Operating Principle

> **Preserve the verified foundation. Define the destination before implementation. Make the smallest justified change. Keep authorization, verification, evidence, provenance, and human control authoritative.**

ARFA is being built incrementally, but it is being architected for the complete platform from the beginning.

---

**End of ARFA_MASTER_CONTEXT.md**
