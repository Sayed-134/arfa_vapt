# ARFA VAPT — Platform Strategy

> **Status:** Strategic reference — long-term vision and architectural direction.
> **Scope:** Defines how ARFA is designed as a platform, not what is implemented today.
> **Relationship to other documents:**
> - `ARCHITECTURE.md` — complete architectural design of the current system
> - `ARFA_MASTER_CONTEXT.md` — current state, closed milestones, active roadmap
> - `PLATFORM_STRATEGY.md` (this file) — long-term vision, extension model, architectural principles
> - **Code** — the actual, verified source of truth for what exists

---

## 1. Vision & Philosophy

ARFA VAPT is designed as a **platform**, not as a scanner that grows features over time.

The founding principle:

> **Design ARFA for the scale of tomorrow's product. Build it incrementally with strict engineering discipline.**

This means:

1. **The architecture describes the complete product we intend to reach** — not only what is implemented today.
2. **The core is stable and versioned** — extensions and new capabilities must not force the core to be rebuilt.
3. **New capabilities are added by extension, not by rewrite** — whether they arrive next month or in ten years.
4. **Planning is big; execution is incremental; engineering discipline is strict.**

ARFA does not set a ceiling on itself based on the capabilities of today's tools, the size of today's team, or the state of today's code.

ARFA also does not use "big vision" as permission to skip contracts, tests, or phasing.

Both statements hold simultaneously. The rest of this document defines how.

---

## 2. The Four Layers

ARFA's development follows four distinct conceptual layers. Confusing them is the source of most architectural drift.

```
┌─────────────────────────────────────────────────────┐
│  ARCHITECTURE                                       │
│  The complete picture of what ARFA is designed      │
│  to become.                                         │
│  → ARCHITECTURE.md                                  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  ROADMAP                                            │
│  The order in which capabilities are reached.       │
│  Updated as the project evolves.                    │
│  → ARFA_MASTER_CONTEXT.md                           │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  PHASE                                              │
│  The specific work being executed now.              │
│  Bounded, tested, reviewable, reversible.           │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  CODE                                               │
│  What is actually implemented and verified.         │
│  The ultimate source of truth.                      │
└─────────────────────────────────────────────────────┘
```

**Rules:**

- Architecture is allowed to describe capabilities that do not exist yet.
- Roadmap is allowed to change.
- Phases are allowed to be small.
- Code is never allowed to lie about itself.

A capability existing in the Architecture does **not** mean it exists in the code.
A capability existing in the Roadmap does **not** mean it is being built now.

---

## 3. Stable Core Contracts

The core is **stable**, not immutable.

Immutability is a myth: even `ScanEnvelope v1` may eventually require `v2`. What matters is that:

- The core defines a small set of **contracts** that everything else depends on.
- Changes to those contracts are **versioned**, **documented**, and **compatible-by-default**.
- Extensions and capabilities are added **around** the core, not by rewriting it.

### Core contracts (stable, versioned)

| Contract | Purpose |
|----------|---------|
| Authorization / Scope | Gate every active operation. Non-negotiable. |
| Scan Job | A unit of scanning work. |
| ScanEnvelope | The JSON boundary between the Go scanner and downstream analysis. |
| Finding | The authoritative result model. Additive extensions only. |
| Verification Status | The currently defined verification statuses as documented in `ARCHITECTURE.md` and implemented in the codebase. |
| Verification Confidence | Additive detail derived from verification evidence. |
| Evidence | Structured, redaction-bounded proof for a finding. |
| Coverage | Endpoint × Parameter × Vulnerability-class tracking. |
| Planner / execution contracts | Deterministic next-action derivation. |
| Pipeline lifecycle | Discovery → Detection → Verification → Evidence → Finding → Report. |
| Reporting contracts | Final JSON output and its schema. |
| Extension contracts | The interfaces by which new capabilities plug in. |

> **Note on Verification Status:** This document does not introduce new verification statuses. The authoritative list is defined by `ARCHITECTURE.md` and the current code. Any future addition to that list is a versioned core change, subject to the rules in §3 and §7.

### The Core Rule

> **An extension must never force a change to the core.**

If an extension requires a core change, one of two things is true:

1. The extension is not yet shaped correctly, and should be reshaped.
2. The core is genuinely missing a capability, and a **versioned** core change is required — with explicit architectural approval, backward compatibility, and regression coverage.

There is no third option.

---

## 4. Extension System

### 4.1 Concept — Multi-Capability

An ARFA extension is **not** "a detector." It is a package that may contribute one or more of the following capabilities:

- Detector
- Verifier
- Analyzer
- Crawler / Discovery capability
- Payload provider
- Evidence processor
- Correlation capability
- Risk capability
- Integration / Bridge
- Language / framework intelligence

An extension is not required to implement all of them. It is required to **declare** which it implements, in its manifest.

**Example:**

```
Extension: java-security
Capabilities:
  - Java framework detection
  - Java-specific detector (deserialization, expression injection, ...)
  - Java-specific payload provider
  - Java-specific verification
```

This is stronger than a flat "Java / PHP / .NET" folder split, because a language by itself is not a capability — the capabilities that a language enables are.

### 4.2 Extension Contract

The architecture must define **what an extension is**, before deciding **how it is loaded**.

At minimum, the contract defines:

- What an extension declares (capabilities, targets, dependencies).
- What an extension is given (core services, configuration, target context).
- What an extension may return (findings, evidence, coverage updates).
- What an extension may never do (modify core contracts, bypass authorization, silently override verification).

The contract is the same regardless of how the extension is packaged or loaded.

### 4.3 Extension Registry

The registry is the core's view of what extensions are available.

Responsibilities:

- Discover extensions
- Register them
- Validate their manifests
- Track their lifecycle state
- Expose their capabilities to the pipeline

The registry does not execute extensions. It knows about them.

### 4.4 Extension Lifecycle

Every extension passes through a defined lifecycle:

```
Discover → Register → Validate → Enable → Configure → Run → Disable → Upgrade → Remove
```

Each transition is explicit. Failure at any stage must be isolated.

### 4.5 Manifest

Every extension carries a manifest describing itself. Required fields:

- `name`
- `id`
- `version`
- `extension_api_version`
- `core_compatibility`
- `capabilities` (list of capability types)
- `dependencies`
- `configuration_schema`
- `supported_targets` / `supported_frameworks`
- `security` / `trust` metadata

Optional metadata:

- `author`
- `description`
- `license`

The manifest is the contract between the extension and the core. The core trusts nothing that is not declared in the manifest.

### 4.6 Trust & Security

Extensions are a security boundary. The architecture must treat them as such from the beginning, even before the extension system is implemented.

Principles:

- An extension **does not automatically gain access** to target traffic, filesystem, network, or secrets.
- Access is **declared** in the manifest and **granted** by policy.
- Extensions may be **isolated** from each other.
- Extensions have **resource limits** (CPU, memory, network, runtime).
- Extensions have **explicit permissions** for any privileged operation.

This is true even when the extension system is only built-in.

### 4.7 Isolation & Failure Handling

> **A failing extension must not bring down the core.**

Every extension invocation is bounded by:

- Timeouts
- Panics / errors caught at the boundary
- Resource limits
- Explicit rollback of partial state

If an extension fails, the pipeline records the failure, coverage reflects an inconclusive outcome for the affected cells, and the scan continues.

### 4.8 Loading & Runtime — Deferred Decision

The architecture must **not** commit to a specific loading/runtime mechanism today.

Possible mechanisms include:

- Built-in (compiled into the binary)
- Process-local plugins
- External processes (e.g. gRPC)
- WebAssembly
- Other mechanisms not yet available

Each has tradeoffs. The correct choice depends on the state of the ecosystem at the time the extension system is implemented.

**What the architecture commits to:**

```
Extension Contract
        ↓
Extension Registry
        ↓
Extension Lifecycle
        ↓
Loader / Runtime   ← implementation decision, per phase
```

The architecture defines the first three. It leaves the fourth open.

The architecture **must** be designed so that external extensions are possible — even if the first implementation is built-in.

---

## 5. Integration Boundary

ARFA does not exist in a vacuum. It must coexist with the rest of the security tooling ecosystem.

### 5.1 Integration as a First-Class Concept

Integration with external tools is an architectural capability, not a feature.

The integration boundary must support, over time:

```
ARFA ↔ Burp Suite
ARFA ↔ ZAP
ARFA ↔ Nuclei
ARFA ↔ other security tools
```

### 5.2 Burp Bridge — Bidirectional

The Burp integration is bidirectional. What may flow across the boundary includes:

- Findings
- Requests / Responses
- Evidence
- Targets
- Scope
- Scan context

Not all of this flows in the first implementation. The architecture must allow all of it.

### 5.3 Proxy Capability — Future, Not Rejected

Using Burp (or a similar tool) as a proxy is a **future capability**, not a rejected one.

It is not committed to today, and it is not excluded from the architecture.

### 5.4 No Tool Is Off-Limits

ARFA does not exclude integration with any tool merely because that tool is strong.

Each integration is evaluated on its value to ARFA and its cost.

### 5.5 Knowledge Sources (Future)

External datasets and curated knowledge sources are classified as **future knowledge sources**. They are not ingested into the current scanner, the Python AI Engine, or the pipeline.

Classification:

- **HackerOne reports** → future vulnerability knowledge / evidence-derived knowledge
- **Bug bounty skills / methodologies** → future methodology / skills knowledge
- **Other datasets** → candidate knowledge sources
- **Mobile pentest toolkit** → future / mobile capability candidate

Ingestion, indexing, retrieval-augmented generation (RAG), training, and integration with the AI Engine are **explicitly deferred**. No ingestion pipeline is implemented until the Knowledge Layer (see §10.5) enters a future phase.

External knowledge sources serve the future Knowledge Layer. They do not replace evidence, and they do not override provenance. Every finding produced with knowledge-layer assistance remains an ARFA finding with its own provenance (§6).

---

## 6. Evidence Provenance

Every finding in ARFA carries **provenance**: a durable record of who produced it, and how.

Minimum provenance fields:

- Who / what produced the finding (core detector, extension, external tool, AI analyzer).
- Which extension and version (if applicable).
- Which detector.
- Which verification method and result.
- Which evidence supports the finding.

Provenance is not optional metadata. It is what makes ARFA findings **reproducible, auditable, and defensible**.

### Why this matters

The ARFA pipeline is:

```
Detection → Verification → Evidence → Confidence → Finding
                                                        ↓
                                Correlation → Attack Chain → Risk → Report
```

Without provenance, the pipeline is opaque. With provenance, every stage can be audited independently.

This is a core differentiator of ARFA: findings that can be **traced** from report back to detector, verifier, and evidence.

### Extending provenance

External tools and extensions must be able to **contribute** to provenance, not replace it.

A finding arriving from Burp or from a Java extension still produces an ARFA finding with its own provenance, marked with the external source.

---

## 7. Versioning & Compatibility

ARFA versions more than code. It versions contracts.

### Versioned surfaces

- Core API version
- Extension API version
- Contract versions (ScanEnvelope, Finding, Evidence, ...)
- Manifest version

### The Compatibility Rule

> **An extension must not break the core.**
> **A core change must not break extensions that have not requested it.**

Breaking changes are:

- Versioned (`v2` alongside `v1` where possible)
- Documented
- Announced via compatibility metadata
- Validated by regression tests

### Deprecation

Old versions remain functional until explicitly removed, and removals follow a documented deprecation policy.

---

## 8. Learning From Existing Tools

ARFA studies the strongest existing tools in the field — including Burp Suite, ZAP, Nuclei, Metasploit, and others — as **sources of capability understanding**, not as competitors to imitate or to dismiss.

For each capability that another tool has proven valuable, ARFA asks:

1. What problem does this capability solve?
2. Why did this tool's implementation succeed?
3. Does ARFA need this capability?
4. If yes, what is the best design for ARFA?

ARFA does not:

- Copy another tool's implementation.
- Claim superiority without a benchmark.
- Reject a capability merely because another tool is strong in it.

ARFA does:

- Take the capability seriously.
- Design it within ARFA's own architecture.
- Implement it in its own phase, with its own contracts and tests.

Where ARFA differentiates is **not** in any single capability. It is in the **integration** of capabilities across a single, evidence-backed, provenance-preserving pipeline.

---

## 9. Scope of Ambition — and Its Limits

### 9.1 No self-imposed ceiling

ARFA does not set a ceiling on itself based on:

- The capabilities of today's competing tools
- The size of the current team
- The state of the current code

Any capability that could serve ARFA's mission is allowed to enter the architecture and roadmap, regardless of size.

### 9.2 No self-imposed rush

Planning for a large product does **not** mean implementing everything at once.

> ARFA plans for the large product from the beginning, and implements it incrementally, with strict engineering discipline at every step.

### 9.3 What this does NOT mean

It does **not** mean:

- Building 50 features at once.
- Abandoning phased execution.
- Skipping contracts, tests, or reviews.
- Treating the architecture as a to-do list.

It **does** mean:

- Knowing the destination before laying the next stone.
- Ensuring today's foundation can host tomorrow's capability without a rewrite.
- Treating "add a new capability" as a normal event, not a crisis.

---

## 10. Architecture vs Roadmap vs Phase

### 10.1 Architecture

Describes the complete product ARFA intends to become. May include capabilities not yet scheduled.

### 10.2 Roadmap

Orders the capabilities described in the architecture. Changes over time. Not a commitment to a specific date.

### 10.3 Phase

The bounded unit of work currently being executed. Has:

- A single scope
- A feature branch
- Tests
- Review
- A merge point
- A freeze point

### 10.4 Historical state snapshot

This section records the state at the time this strategy document was
created. It is not current project status. For the authoritative current
state, see ARFA_MASTER_CONTEXT.md.

At the time of this document's creation:

- Phase 4 — Technical Debt was in progress.
- TD #1 was the next candidate.
- No new phase was open.

> **This section is a snapshot, not a permanent contract.**
> The authoritative, always-current state of phases, milestones, and technical debt is maintained in `ARFA_MASTER_CONTEXT.md`. If this section and `ARFA_MASTER_CONTEXT.md` disagree, `ARFA_MASTER_CONTEXT.md` wins.

### 10.5 Future capability roadmap

After the current phase closes, capability work proceeds through the intake process described in §15. Candidate capabilities include (but are not limited to):

- Authenticated scanning
- Out-of-band (OOB) verification
- JavaScript / browser-based crawling
- Multi-target orchestration
- Agentic bounded-loop execution
- Extension system implementation
- External tool integrations
- Web3 scanning
- Mobile scanning
- Knowledge / persistence layer
- **Knowledge Layer (Zetsu)** — a future knowledge and methodology layer providing structured access to security methodologies, skills, vulnerability reports, external datasets, and other curated knowledge sources. Intended to support analysis, correlation, planning, verification, and future agentic decision-making, while preserving provenance and evidence boundaries. Implementation is deferred to a future phase.
- Dashboard / UI
- **Extended HTTP capabilities** — multipart / file upload, JSON request bodies, PUT / PATCH / DELETE, cookies / session-aware requests, CSRF handling, GraphQL, WebSocket. Recorded as future candidates; not scheduled, not TDs, and not part of any current phase.

Order is determined by the intake process, not by this document.

---

### Additional Future Capability Candidates

The following capabilities are accepted as future roadmap candidates only.
They are not part of the current Phase 4 implementation and do not reopen
or modify any closed TD.

- **Detector Coverage Expansion**
  - Systematic expansion of vulnerability detection beyond the currently
    implemented detector set.
  - Candidate areas may include command injection, LDAP injection, NoSQL
    injection, SSRF, SSTI, open redirect, WebSocket/GraphQL-specific
    vulnerabilities, and other validated vulnerability classes.
  - New detectors must preserve the existing deterministic Detection →
    Verification → Evidence → Finding pipeline, verification semantics,
    evidence/provenance requirements, coverage tracking, and Go
    source-of-truth rules.
  - Exact detector priorities and phase placement will be determined
    after Phase 4 completion and capability-gap review.

- **Managed / ARFA-Owned Payload Corpus**
  - Future evaluation of an ARFA-managed, versioned payload corpus in
    addition to the currently used external corpus.
  - The goal is broader detector coverage, controlled maintenance,
    provenance, reproducibility, and predictable release behavior.
  - This does not replace the existing corpus or alter TD #6 / TD #16.
  - Corpus ownership, synchronization, packaging, licensing, maintenance,
    and release strategy must be evaluated before implementation.
  - No new corpus implementation is part of the current phase.

- **Modern Web / SPA Discovery**
  - The existing Headless Browser Adapter boundary may be used in a
    future phase for JavaScript execution, SPA route discovery, dynamic
    API discovery, DOM observations, and browser-assisted verification.
  - This supplements the deterministic crawler; it does not replace it.
  - The capability must preserve authorization/scope, endpoint identity,
    deterministic core behavior, verification semantics, and
    evidence/provenance.
  - Implementation remains deferred to a future phase.

These candidates are intentionally not assigned fixed phase numbers yet.
Phase ordering will be determined through the Future Capability Intake
process after the current Phase 4 work is complete and the actual
capability gaps are re-evaluated.

## 11. Baseline & KPIs

### 11.1 Principle

Every meaningful capability change is preceded by a **baseline measurement** of the affected metric, and followed by a comparison against it.

### 11.2 What this means

- No capability is declared "better" without a benchmark.
- No claim of "faster" or "more accurate" without a baseline.
- Numbers stated in strategy or marketing must be reproducible from a run.

### 11.3 Candidate metrics

Metrics are chosen per phase, not fixed globally. Candidates include:

- False positive rate
- True positive detection rate
- Scan duration
- Throughput (URLs per unit time)
- Maximum practical target size
- Coverage per vulnerability class
- Verification coverage

### 11.4 Rule

A metric without a reproducible measurement method is not a metric. It is a wish.

---

## 12. Decision Log

Every substantial architectural or strategic decision is recorded — not just made.

### 12.1 What a decision record contains

- Date
- Decision
- Reason
- Alternatives considered
- Status (accepted / rejected / deferred)
- Consequences

### 12.2 Where it lives

The decision log lives in `PLATFORM_STRATEGY.md`, under this section. It is part of the strategic reference and is updated when a decision is made, reversed, or materially changed.

### 12.3 Why

- Prevents re-litigating settled questions.
- Preserves context for future contributors (human and AI).
- Makes reversals explicit and auditable.

### 12.4 Recorded decisions

**2026-09-14 — Zetsu and external knowledge sources documented**

- **Decision:** Zetsu is documented as a future architectural layer. External datasets (HackerOne reports, bug bounty methodologies, other curated sources) are classified as future knowledge sources.
- **Reason:** Zetsu is a substantive part of the intended platform, not a passing idea. It belongs in the strategic vision so that future contributors (human and AI) know it has an architectural home.
- **Alternatives considered:**
  - Decision Log entry only — rejected. Zetsu is architectural, not merely a decision.
  - Build Zetsu now — rejected. Violates phase discipline.
- **Status:** accepted (documentation only; no implementation)
- **Consequences:**
  - `PLATFORM_STRATEGY.md` gains an explicit Zetsu entry (§10.5)
  - `PLATFORM_STRATEGY.md` gains §5.5 Knowledge Sources (Future)
  - External datasets remain outside the repository, retained as future materials
  - No ingestion, no RAG, no training, no AI Engine integration
  - No new phase is opened
  - Implementation is deferred to a future phase

**2026-09-16 — TD #2 Endpoint Identity & Form Parameter Transport**

- **Decision:**
  TD #2 establishes first-class GET and POST
  (`application/x-www-form-urlencoded`) form support within its defined scope,
  while preserving GET backward compatibility and maintaining an execution
  boundary that can accommodate future HTTP methods and body types without
  requiring redesign of the scanner/detector pipeline.

- **Endpoint Identity:**
  `(URL, Method)` is the Endpoint identity.
  - Same URL + same Method → one endpoint; parameters are unioned and deduplicated.
  - Same URL + different Method → separate endpoints.

- **Parameter Transport:**
  - GET  → `Parameters` → query string
  - POST → `FormParameters` → `application/x-www-form-urlencoded` body

- **In Scope:**
  - GET/POST form discovery
  - Form field extraction (`input` / `textarea` / `select`)
  - Method-aware request construction
  - Form field → job/coverage integration
  - Tests and regression protection

- **Out of Scope (recorded in the Future Capability Roadmap):**
  - multipart / file upload
  - JSON request bodies
  - PUT / PATCH / DELETE
  - Cookies / session-aware requests
  - CSRF handling
  - GraphQL
  - WebSocket

- **Reason:**
  GET-only discovery is insufficient for meaningful web VAPT coverage.
  TD #2 establishes POST form-urlencoded as a first-class capability while
  keeping the HTTP execution boundary suitable for future extension.

- **Alternatives Considered:**
  - Minimal implementation (`Do(url, params)` + method-specific conditionals) —
    rejected as too tightly coupled to the current query-only transport.
  - Full abstraction (`BodyStrategy`, `JSONBodyStrategy`, etc.) —
    rejected as premature abstraction.
  - **Minimal Scope + Professional Foundation** — accepted.

- **Status:**
  Implemented and **CLOSED / FROZEN** on 2026-09-17 via PR #8.

- **Implementation outcome:**
  - HTML form discovery supports GET and POST.
  - Form fields are extracted from `input`, `textarea`, and `select` elements.
  - Endpoint identity is `(URL, Method)`.
  - GET parameters use the query string.
  - POST parameters use `application/x-www-form-urlencoded` request bodies.
  - Scanner job generation, coverage seeding, and raw probing are method-aware.
  - Existing GET behavior remains backward-compatible.
  - No new dependency was introduced.

- **Validation outcome:**
  - Focused crawler/HTTP-client/scanner tests — PASS
  - `go test ./...` — PASS
  - `go test -race ./...` — PASS
  - `go vet ./...` — PASS
  - `go build ./...` — PASS
  - `scripts/run_e2e_regression.sh` — PASS after updating the stale finding-count baseline from 3 to 4
  - GitHub CI — 2/2 checks PASS
  - PR #8 — MERGED to `main`

- **Consequences:**
  - Endpoint map identity is now `(URL, Method)`.
  - `effectiveParams` is method-aware.
  - `rawProbe` is method-aware.
  - `httpclient.Do()` accepts a method-aware request model.
  - No completed Phase or TD was reopened.

- **Future Capability Roadmap reference:**
  The "Out of Scope" items above are recorded in
  `PLATFORM_STRATEGY.md §10.5 — Extended HTTP capabilities`.

TD #2 is now closed/frozen. Future work on multipart, JSON bodies, additional HTTP methods,
cookies/session context, CSRF, GraphQL, or WebSocket remains outside TD #2 and must enter through
the normal future-capability intake and phase process.


---

## 13. Non-Goals

ARFA does not pursue the following, absent a specific reversal recorded in the decision log:

1. **Rewriting the core to chase a competitor's feature.** Capabilities are added around the core, not by replacing it.
2. **Copying another tool's implementation.** Capabilities are understood, not copied.
3. **Claiming superiority without a benchmark.** Every claim is measurable.
4. **Opening new phases while the current phase is open.** Phase discipline is non-negotiable.
5. **Changing the core contract in a phase that did not request it.** Contract changes require explicit approval.
6. **Implementing future capabilities prematurely.** Architecture allows them; phases schedule them.
7. **Treating the architecture as a to-do list.** Architecture is direction; phases are work.

---

## 14. Rules for Claude (and Other AI Assistants)

When Claude or another AI assistant works on ARFA, the following rules apply.

### 14.1 Before any substantial work

1. Read `ARCHITECTURE.md`, `ARFA_MASTER_CONTEXT.md`, and this document.
2. Read the actual source code relevant to the task.
3. Confirm the current phase and its scope.
4. Confirm no other phase is open.

### 14.2 During work

1. Do not modify the Stable Core without explicit approval.
2. Do not restructure the repository to match a conceptual model in a document.
3. Do not implement capabilities that are not part of the current phase.
4. Do not create backups, `.bak` folders, or duplicate project copies. Git is the recovery mechanism.
5. Do not invent capabilities and claim they exist. If something is not verified in the code, it does not exist.

### 14.3 After work

1. Run all relevant tests.
2. Report exact commands and results.
3. Never claim a test passed if it was not run.
4. Never claim a capability exists if it is not verified in the repository.
5. Commit only after validation.
6. Do not merge to `main` without explicit instruction.

### 14.4 When in doubt

Ask. Architectural decisions belong to the human owner, not to the assistant.

---

## 15. Future Capability Intake

ARFA will receive new capability ideas continuously — during development, after release, and years into the future. This section defines how such ideas are handled.

### 15.1 The intake process

```
New capability proposed
        ↓
Architecture fit?         — Does it belong in ARFA at all?
        ↓
Core change or Extension? — Can it be added without touching the core?
        ↓
Dependencies?             — What does it require from other parts?
        ↓
Security / isolation?     — Does it introduce new trust boundaries?
        ↓
Evidence / provenance?    — How does it affect finding traceability?
        ↓
Roadmap placement         — Where does it sit in the ordering?
        ↓
Phase implementation      — When does it actually get built?
```

### 15.2 Rules

- A capability is not rejected merely because it is large.
- A capability is not accepted into implementation merely because it is attractive.
- Every accepted capability enters the architecture first, then the roadmap, then a phase — in that order.
- **A capability may be added to the architecture without being added to the current phase.**
- No capability skips the intake process.
- The output of intake is a decision record (§12).

### 15.3 What this achieves

- New ideas are not lost.
- New ideas are not rushed.
- The architecture grows steadily, without rewrites.
- Every contributor — human or AI — knows exactly where a new idea belongs.

---

## Authorized Identity & Session Management

ARFA's future platform strategy includes a dedicated capability for managing authorized testing identities and authentication sessions.

The capability is intended to support:

- Provisioning authorized test accounts when the testing scope permits account creation.
- Secure credential and authentication-secret storage through a dedicated vault boundary.
- Authentication and session lifecycle management.
- Reusable authorized identities and sessions across subsequent scans.
- Multiple principals for IDOR and authorization-boundary testing.
- Identity-aware evidence, findings, and reporting using safe references rather than raw secrets.
- Credential lifecycle management including rotation, update, disablement, and deletion.

All identity, account, authentication, and session operations must remain explicitly bounded by the authorized testing scope. Raw credentials and authentication secrets must remain outside findings, reports, scan history, and normal evidence.

This capability is a future platform layer and is not part of the current TD #11 implementation. It will integrate with TD #11's existing `AuthContext` contract rather than replace or redesign it.

For the detailed architectural definition, see `ARCHITECTURE.md — Authorized Identity & Session Management Layer — Future`.

## 16. Source of Truth

When documents disagree, the following order applies:

1. **The actual source code** — what is implemented and verified.
2. **`ARFA_MASTER_CONTEXT.md`** — current state, closed milestones, active phases.
3. **`ARCHITECTURE.md`** — complete architectural design.
4. **`PLATFORM_STRATEGY.md`** (this document) — long-term vision and principles.

Strategy never overrides architecture.
Architecture never overrides state.
State never overrides code.

---

## 17. Closing Principle

> **ARFA does not start small. ARFA plans for the product it intends to become, and builds it incrementally with strict engineering discipline.**

Every decision in this document serves that principle:

- The core is stable, so extensions can grow safely.
- The extension model is defined, so new capabilities have a home.
- Integration is architectural, so tools are partners, not threats.
- Provenance is first-class, so findings are defensible.
- Versioning is disciplined, so the platform does not break as it grows.
- Intake is defined, so new ideas are neither lost nor rushed.

This is what it means to design for the scale of tomorrow's product — while building with the discipline of today.

---

**End of PLATFORM_STRATEGY.md**

## Architectural Boundary Clarification — Future Input & Observation

The future platform direction explicitly treats the following as additive adapter/analysis boundaries:

- **Traffic / Input Adapters:** HAR, Burp, mitmproxy/proxy traffic, and other external request/response sources are normalized at an adapter boundary and must not become core data models.
- **Observation / Differential Analysis:** baseline and test observations may be compared using status, headers, length, timing, reflection, and behavioral differences. These differences are analysis signals, not findings by themselves.
- **OOB Interaction Adapter:** external OOB providers may return interaction events correlated to the originating authorized probe before Verification/Evidence. The core does not implement an OOB server.
- **Headless Browser Adapter:** Playwright/Chromium may provide JavaScript/SPA discovery, DOM observations, and browser-assisted verification as an additional Discovery/Observation capability. It supplements, rather than replaces, the deterministic crawler.

All four boundaries preserve authorization/scope, `(URL, Method)` endpoint identity, existing verification semantics, evidence/provenance, and core independence from any specific external tool or runtime.

These are architectural boundaries only; implementation remains deferred to its appropriate future phase.
