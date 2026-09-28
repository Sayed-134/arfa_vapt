# ARFA VAPT — Final Platform Architecture

## 1. Purpose

ARFA VAPT is an authorized security assessment and security intelligence platform designed to assess modern applications, APIs, mobile applications, Web3 systems, browser-based applications, network/service-facing surfaces, and integrated external security tooling.

This document defines the long-term architecture and the boundaries that implementation phases must follow. It is an architectural contract, not a statement that every described capability already exists.

The repository source code remains the source of truth for implemented behavior. Architecture defines the intended system, stable boundaries, compatibility rules, and phase direction.

ARFA follows:

> **Preserve proven foundations. Evolve where necessary. Rebuild only when justified by an explicit architectural decision.**

Architecture is defined before implementation. A capability may exist in this document long before it is scheduled for a phase.

---

# 2. Architectural Objectives

ARFA must evolve from the current deterministic HTTP/API assessment core into a unified, evidence-backed assessment platform without replacing the verified foundation unnecessarily.

The architecture must support:

- Web applications and APIs
- Browser and JavaScript-heavy applications
- HTTP/HTTPS interception and traffic analysis
- Authentication and authorization testing
- Mobile Android and iOS assessment
- Web3, smart contracts, wallets, dApps, and blockchain RPC
- External attack-surface discovery and continuous recon
- Broad vulnerability discovery across supported domains and technologies
- OAST / out-of-band verification
- Race and concurrency testing
- External security-tool integrations
- AI-assisted analysis, correlation, prioritization, hypotheses, and bounded next actions
- Evidence-backed attack chains and correlation
- Historical and regression assessment
- Continuous assessment
- Repeater, Intruder, traffic history, application mapping, and browser workflows
- Extensibility through a controlled extension system
- Local, team, and future enterprise deployment models
- Human approval for operations that require elevated or destructive authority

The architecture must not impose an artificial ceiling on vulnerability classes. New vulnerability classes, payloads, protocols, verification methods, discovery methods, and domain-specific engines must be addable without redesigning the platform core.

---

# 3. Architectural Principles

1. **Authorized execution only.** Every active operation is bounded by explicit authorization and scope.
2. **Deterministic truth path.** Authoritative findings require evidence and verification according to registered verification policy.
3. **AI is not the source of security truth.** AI may reason over observations and propose actions, but cannot silently manufacture authoritative findings or override policy.
4. **Capability independence.** HTTP, browser, traffic, mobile, Web3, OAST, and external tools may use domain-native implementations behind common contracts.
5. **Smallest necessary change.** Existing verified behavior is preserved unless an explicit architectural need justifies evolution.
6. **Bounded autonomy.** Every autonomous or semi-autonomous workflow has scope, capability, budget, time, rate, and approval boundaries.
7. **Evidence and provenance are first-class.** Findings must be traceable to observations, execution attempts, verification, and evidence.
8. **Readiness is distinct from coverage.** A target that cannot be meaningfully assessed must not be represented as equivalent to a clean assessment.
9. **Security boundaries are explicit.** Secrets, network access, browser state, external tools, plugins, and privileged operations receive controlled capabilities.
10. **Local-first evolution.** The initial platform remains operable as a coherent local deployment. Distributed infrastructure is introduced only when measured scale requires it.
11. **Contracts before implementations.** Stable interfaces define integration points; implementation technology may change behind them.
12. **Observable and recoverable execution.** Long-running work must survive cancellation, retries, crashes, duplicate delivery, and late results without corrupting assessment truth.
13. **Backward compatibility by default.** Existing contracts remain readable and usable unless a versioned architectural change is explicitly approved.
14. **Architecture is not the roadmap.** This document describes the destination and boundaries; phases decide what is implemented next.

---

# 4. Current Foundation

The existing ARFA foundation is a deterministic Go security-scanning core with a Python intelligence layer.

The verified foundation includes, among other components:

- Authorization acknowledgement and scope handling
- `ScanEnvelope` with `arfa.scan/v1`
- HTTP reachability and crawling
- Endpoint and parameter handling
- Deterministic detector execution
- Rate limiting and bounded execution
- Adaptive budgets
- Coverage tracking
- Deterministic planning / `NextActions`
- Verification and bounded verification attempts
- Control probes
- Verification caching / single-flight behavior
- Evidence collection and redaction
- Verification confidence as supporting information
- Auth context for authorized principal-aware testing
- Scan history / persistence
- Python AI analysis downstream of Go scan facts

These foundations are preserved. The platform architecture expands around them rather than replacing them wholesale.

Some current implementation details remain intentionally narrower than the final architecture. For example, current HTTP preflight is not the complete future readiness system, and current endpoint/category coverage is not the final cross-domain coverage representation.

---

# 5. System Topology

ARFA uses three logical architectural planes.

```text
┌──────────────────────────────────────────────────────────┐
│                    CONTROL PLANE                         │
│ Assessment • Scope • Policy • Scheduling • Jobs          │
│ State • Coverage Obligations • Verification Authority    │
│ Evidence References • Findings • Audit • Approvals       │
└───────────────────────┬──────────────────────────────────┘
                        │
                        │ constrained execution contracts
                        ▼
┌──────────────────────────────────────────────────────────┐
│                 EXECUTION AGENTS / ENGINES               │
│ HTTP • Traffic • Browser • Mobile • Web3 • OAST          │
│ Discovery • External Tools • Future Domain Engines       │
└───────────────────────┬──────────────────────────────────┘
                        │ observations / artifacts
                        ▼
┌──────────────────────────────────────────────────────────┐
│                INTELLIGENCE / KNOWLEDGE                  │
│ AI • Correlation • Risk • Attack Chains • Knowledge      │
│ Reporting • Recommendations • Bounded Agent Reasoning    │
└──────────────────────────────────────────────────────────┘
```

These are logical boundaries first. The initial deployment may run them in one modular application with embedded workers and selected process isolation. Separate services, brokers, or remote workers are introduced only when security, scale, reliability, or deployment requirements justify them.

The architecture therefore does **not** require an early microservice or distributed-system rewrite.

---

# 6. Control Plane

The Control Plane is the authoritative owner of assessment policy and assessment state.

It is responsible for:

- Assessment lifecycle
- Run lifecycle
- Authorization and scope policy
- Capability grants
- Execution budgets
- Scheduling
- Job state
- Action identity and idempotency
- Cancellation and recovery
- Coverage obligations and outcomes
- Readiness state
- Verification decisions
- Evidence references
- Finding authority
- Approval gates
- Audit records
- Provenance
- Historical comparison
- Continuous-assessment scheduling

Execution engines must not silently redefine these policies.

The Control Plane may request execution from an engine, but an engine receives only the authority required for that operation.

---

# 7. Assessment and Run Model

ARFA uses an explicit hierarchy:

```text
Assessment
  ├── immutable authorization/scope snapshot
  ├── policy snapshot
  ├── identities / sessions references
  ├── assets / attack surface
  ├── coverage obligations
  ├── findings lifecycle
  └── Runs
        ├── Run 1
        ├── Run 2
        └── ...
```

An **Assessment** represents the authorized security-testing context and its historical lifecycle.

A **Run** represents one bounded execution instance within that assessment.

This enables:

- Repeated assessments
- Regression testing
- Continuous assessment
- Finding lifecycle tracking
- Run-to-run comparison
- Historical evidence
- Resume/recovery
- Incremental attack-surface updates

The existing scan concept remains compatible with the Run model.

---

# 8. Execution Contract

All execution-capable engines integrate through a common conceptual contract. The exact language and transport may differ by engine.

```text
Execution Request
      ↓
Authorized Attempt
      ↓
Observation(s)
      ↓
Artifact Reference(s)
      ↓
Execution Result
      ↓
Verification
      ↓
Evidence
      ↓
Authoritative Finding (when justified)
```

A request must be able to carry, conceptually:

- Assessment / Run identity
- Scope authorization reference
- Asset reference
- Action specification
- Identity / session context reference
- Required capabilities
- Safety / test intent
- Budget
- Timeout
- Correlation / Action ID
- Provenance

An execution engine returns observations and artifacts. It does not bypass the authoritative verification boundary merely because it is domain-specific.

---

# 9. Action Identity, Idempotency, and Recovery

Every meaningful execution action must have a stable identity and lifecycle.

The platform must account for:

- Action ID
- Attempt number
- Queued state
- Running state
- Completed state
- Failed state
- Cancelled state
- Timed-out state
- Partial result state
- Artifact upload state
- Verification state

The architecture must tolerate:

- Duplicate delivery
- Retry after process failure
- Late browser results
- Late OAST callbacks
- External-tool completion after cancellation
- Partial artifact persistence
- Worker termination
- Control-plane restart

Duplicate or late results must not silently create duplicate authoritative findings.

---

# 10. Scope, Authorization, Capabilities, and Egress

Authorization is not merely a CLI acknowledgement. It is an execution security boundary.

The platform must enforce scope and capability policy across every execution boundary, including:

- HTTP
- Browser
- Proxy / Traffic
- DNS
- Redirect handling
- Mobile devices/emulators
- Web3 RPC
- OAST callbacks
- External tools
- Plugins
- Future workers

A proxy alone is insufficient as the scope boundary.

Where applicable, the system must revalidate destinations after:

- DNS resolution
- Redirects
- Alternate network addresses
- Proxy routing
- Tool-generated targets
- Browser navigation
- External-tool discovery

Capabilities must be explicit. Examples include:

- Network egress
- Subprocess execution
- Browser control
- Artifact access
- Secret/vault access
- Device/emulator access
- Wallet operations
- OAST registration
- Traffic interception

A component receives only the capabilities granted to its action.

---

# 11. Identity, Session, and Vault Model

Identity is a first-class security-testing context.

ARFA distinguishes at least:

- Test identity / principal
- Role
- Credential
- Authentication session
- Browser context
- Device identity
- Mobile application identity
- Wallet identity
- API authentication context

Sensitive credentials and secrets belong behind a dedicated vault boundary.

Findings, evidence, reports, and history must use safe references such as:

```text
IdentityRef
SessionRef
CredentialRef
WalletRef
```

rather than raw secrets.

TD #11's `AuthContext` remains a foundation for principal-aware testing. Future identity/session management integrates with it rather than replacing it.

Any account creation, authentication, credential use, or session manipulation must be explicitly authorized.

---

# 12. Observation, Evidence, Verification, and Finding

These are separate concepts and must remain separate in the architecture.

```text
Observation
   ↓
Evidence / Artifact
   ↓
Verification Verdict
   ↓
Finding
```

### Observation

A fact produced by execution, discovery, comparison, a browser, an external tool, a callback, a device, a blockchain runtime, or another authorized engine.

### Evidence

A bounded, provenance-preserving representation supporting analysis or verification.

### Verification

The authoritative decision process that determines whether an observation/evidence set justifies a verification state.

### Finding

An authoritative security result produced only through the platform's verification boundary.

Detection signals, AI output, external-tool output, and differential-analysis signals do not automatically become findings.

---

# 13. Verification Architecture

Verification is a framework, not a single HTTP implementation.

Verification strategies may be domain-native while obeying common requirements for:

- Scope
- Authorization
- Bounded execution
- Evidence
- Provenance
- Reproducibility
- Verification state
- Confidence information

Examples include:

- HTTP repeat/control verification
- Browser execution verification
- DOM/runtime verification
- OAST correlation verification
- Mobile dynamic verification
- Web3 transaction/trace verification
- Differential verification
- Race/concurrency verification
- State-transition verification

No vulnerability category is considered universally confirmed without an appropriate verification strategy.

Existing verification statuses remain authoritative unless a versioned architectural change is explicitly approved.

---

# 14. Evidence Custody

Evidence must be treated as security-sensitive data, not arbitrary logging.

The evidence architecture must support:

- Content addressing
- Integrity verification
- Immutable references
- Provenance
- Redacted and, where authorized, raw representations
- Encryption for sensitive artifacts
- Access control
- Retention policy
- Deletion/tombstone semantics
- Auditability
- Artifact deduplication
- Partial-upload recovery

Evidence types may include:

- HTTP request/response excerpts
- Sanitized headers
- Screenshots
- DOM snapshots
- Browser state references
- HAR-like traffic artifacts
- Mobile logs
- APK/IPA analysis artifacts
- Smart-contract traces
- State diffs
- OAST interaction records
- External-tool output

Raw secrets must not be copied into normal evidence merely because they were visible during execution.

---

# 15. Coverage Model

The current endpoint × parameter × vulnerability-category model remains compatible with the architecture, but it is not the long-term source of truth.

The long-term source of truth is a sparse set of **Test Obligations and Outcomes**.

A test obligation represents something ARFA intends to assess under a particular applicable context.

Conceptually:

```text
Test Obligation
  ├── Subject / Asset
  ├── Capability / Test Type
  ├── Applicable Context
  ├── IdentityRef (when relevant)
  ├── Protocol (when relevant)
  ├── Browser/Device State (when relevant)
  └── Policy/Budget context

Outcome
  ├── NotAttempted
  ├── Attempted
  ├── Failed
  ├── Inconclusive
  ├── Verified
  └── NotApplicable / Blocked where defined by contract
```

The platform must not persist a giant Cartesian product of every possible dimension.

Context dimensions are included only when they materially affect the obligation.

**Readiness is not a coverage dimension.** Readiness describes whether a subject/context is assessable; coverage describes what was attempted and what resulted.

Existing coverage can therefore evolve incrementally into the obligation/outcome model without discarding historical compatibility.

---

# 16. Assessment Readiness

Readiness is a first-class assessment state independent of findings and coverage.

At minimum, the architecture must be able to represent:

- Transport reachable
- Transport inaccessible
- Authentication required
- Browser required
- JavaScript required
- Challenge/interstitial detected
- Rate limited
- Partially accessible
- Insufficient surface discovered
- Degraded
- Unsupported
- Fully assessable

Readiness may exist at multiple levels:

```text
Transport Readiness
Application Readiness
Authentication Readiness
Discovery Readiness
Execution Readiness
```

A successful DNS/TCP/HTTP response does not prove that the application surface was meaningfully assessed.

Reporting must make incomplete assessment explicit.

> **Zero findings is not equivalent to zero vulnerabilities when assessment readiness or coverage is incomplete.**

---

# 17. Asset and Attack-Surface Model

ARFA requires a unified asset model capable of representing heterogeneous security surfaces.

The model may include:

- Assessment
- Domain
- Subdomain
- IP
- Port
- Service
- Application
- API
- Endpoint
- Parameter
- Technology
- Certificate
- Identity
- Role
- Session
- Browser state
- Mobile application
- Mobile component
- Contract
- Contract function
- Wallet
- External service
- Device/emulator
- OAST endpoint

Relationships may include:

- `parent_of`
- `hosts`
- `exposes`
- `observed_on`
- `authenticated_as`
- `belongs_to`
- `calls`
- `references`
- `uses`
- `depends_on`

The initial implementation should use relational records and explicit relationship tables/materialized traversal views. A graph database is not an architectural requirement and must be introduced only if measured workload demonstrates a real need.

---

# 18. Discovery and Attack-Surface Management

Discovery is a capability family rather than one crawler.

Discovery sources may include:

- HTTP crawler
- Browser navigation
- Passive DNS
- Certificate transparency
- DNS enumeration
- Authorized port/service discovery
- OpenAPI
- GraphQL schemas/introspection where authorized
- Source-code/artifact analysis
- APK/IPA analysis
- Smart-contract metadata
- External tools
- Traffic history
- Webhooks and observed integrations

All discovery results become observations/assets and remain subject to scope policy.

Continuous recon is implemented as scheduled assessment workflows over the same architecture, not as a disconnected scanner.

---

# 19. HTTP and API Engine

The existing Go HTTP path remains the first reference execution engine.

It must continue to provide deterministic:

- Request generation
- Rate limiting
- Adaptive budgets
- Detector execution
- Verification
- Evidence collection
- Coverage updates

The HTTP engine should grow to support the broader API/web protocol surface where justified, including:

- HTTP/1.1
- HTTP/2
- HTTP/3/QUIC where practical
- REST
- OpenAPI
- GraphQL
- gRPC/Protobuf
- Webhooks
- OAuth/OIDC
- JWT
- Cookies/sessions
- Multipart/file uploads
- JSON and structured request bodies

Protocol support is an execution capability, not a reason to redesign the assessment core.

---

# 20. Traffic and Interception Subsystem

Traffic is a core ARFA capability.

The subsystem must support, as appropriate:

- Local proxy/interception
- HTTPS interception
- Request/response capture
- Sanitized traffic history
- Application/site map
- Request replay / Repeater
- Parameterized attack generation / Intruder
- Browser-to-traffic correlation
- Scanner-to-traffic correlation
- Finding/evidence-to-traffic correlation
- WebSocket traffic
- SSE traffic
- GraphQL traffic
- Long-lived connection handling

The architecture does **not** commit prematurely to Go, Rust, or another implementation language for the traffic hot path. Technology selection must be driven by protocol coverage, TLS/MITM requirements, throughput, stability, desktop integration, and benchmark evidence.

Traffic artifacts must use the common observation/evidence/provenance model rather than becoming an alternative source of truth.

---

# 21. Browser Engine

The browser is a first-class assessment engine, not merely a UI automation utility.

It must support:

- Isolated browser contexts
- Identity/session separation
- JavaScript execution
- SPA discovery
- DOM inspection
- Network observation
- Runtime/browser events
- Screenshots
- Visual state/diff evidence
- Browser-state persistence where authorized
- Replayable navigation/actions
- Browser-to-traffic correlation
- Browser-to-finding/evidence correlation

The architecture does not permanently lock the browser engine to a single controller technology. Chromium/CDP, Playwright, or another mature implementation may be selected according to reproducibility, protocol coverage, isolation, and operational requirements.

Browser execution must have a direct execution mode where proxy mediation is not technically appropriate, while preserving scope and egress controls.

---

# 22. Mobile Security Engine

Mobile assessment is a dedicated domain engine behind the execution contract.

Android capabilities may include:

- APK/static analysis
- Manifest/component analysis
- Endpoint and secret discovery
- Dynamic emulator/device analysis
- Runtime instrumentation
- Network/API traffic analysis
- Certificate/security-control analysis
- Local storage analysis

iOS capabilities may include:

- IPA/static analysis
- Application/component analysis
- Dynamic simulator/device analysis where supported
- Runtime instrumentation where supported
- Network/API analysis
- Storage and security-control analysis

Mobile execution may require domain-native runtimes and device infrastructure. It must still return normalized observations, artifacts, and provenance to the Control Plane.

Unsupported device/runtime conditions must be represented honestly as readiness/degraded states.

---

# 23. Web3 Security Engine

Web3 is a first-class assessment domain.

The architecture must support:

- Smart-contract source/bytecode analysis
- ABI and function modeling
- Contract discovery
- Static analysis
- Dynamic transaction simulation
- Forked-chain execution where appropriate
- Call traces
- State diffs
- Event/log analysis
- RPC interaction
- Wallet identities
- dApp/browser interaction
- Authorization and signing boundaries

Web3 execution must not be forced into an HTTP-only vulnerability model. Domain-native execution and verification are expected.

Transactions that can change external state require explicit authorization and safety policy. Simulation/forked execution should be preferred where it satisfies the test objective.

---

# 24. OAST / Out-of-Band Verification

OAST is a dedicated verification capability.

It must support:

- Unique interaction tokens
- DNS callbacks
- HTTP callbacks
- Assessment-scoped correlation
- Expiration/TTL
- Delayed callbacks
- Replay handling
- Cancellation races
- Evidence linkage
- Verification integration
- Ingress controls
- Isolation between assessments

OAST tokens must be unpredictable and scoped. A callback alone is not automatically a finding; it must be correlated with an authorized originating action and passed through verification.

---

# 25. Race and Concurrency Testing

Race testing is an execution pattern, not a vulnerability category.

The architecture must support:

- Synchronized request dispatch
- Last-byte synchronization where appropriate
- Controlled concurrency
- Reproducible attempt IDs
- Response comparison
- Side-effect comparison
- State invariant checks
- Evidence collection

Concurrency testing must have explicit safety intent and stronger approval/budget controls when operations can change target state.

Fixed timing thresholds alone must not be treated as universal proof of a race condition.

---

# 26. External Security Tools

External tools are integrated as constrained execution engines/adapters.

Examples may include tools for:

- Network/service discovery
- Subdomain discovery
- HTTP enumeration
- Vulnerability discovery
- Static analysis
- Mobile analysis
- Web3 analysis

An external tool follows:

```text
Authorized Scope
      ↓
Tool Adapter
      ↓
Execution
      ↓
Observation / Artifact
      ↓
Normalization
      ↓
Verification
      ↓
Evidence / Finding
```

External-tool output is not authoritative merely because a tool reported it.

Tool execution must declare required capabilities such as subprocess, filesystem, or network access.

---

# 27. Plugin / Extension Architecture

ARFA uses a capability-oriented extension model.

Conceptually:

```text
Extension Contract
        ↓
Registry
        ↓
Lifecycle
        ↓
Runtime
```

Extensions may contribute:

- Detectors
- Payloads
- Discovery
- Verification strategies
- Protocol support
- Traffic handlers
- AI providers
- Knowledge sources
- External-tool adapters
- Report formats
- Correlation/risk logic

The architecture defines the contract before committing to a runtime technology.

Possible runtimes may include built-in modules, isolated processes, gRPC/JSON-RPC, WASM, or future mechanisms. Runtime choice is governed by security, performance, compatibility, and operational requirements.

Every extension must declare:

- Identity/version
- Extension API compatibility
- Capabilities
- Dependencies
- Configuration schema
- Target/domain applicability
- Trust level
- Required permissions

Third-party extensions must not automatically gain access to:

- Arbitrary network destinations
- Secrets
- Filesystem
- Browser state
- Evidence
- Other assessments
- Privileged operations

The platform must support resource limits, revocation, audit records, and explicit capability grants.

---

# 28. AI and Knowledge Architecture

AI is an intelligence layer over authoritative assessment facts.

AI may:

- Analyze observations
- Correlate findings/signals
- Prioritize work
- Generate hypotheses
- Suggest next actions
- Explain evidence
- Generate narratives/reports
- Build candidate attack chains
- Assist with methodology and knowledge retrieval

AI may not:

- Override authorization
- Expand scope
- Override budgets
- Execute privileged operations without policy authorization
- Convert an unverified signal directly into an authoritative finding
- Silently change scanner facts
- Hide incomplete assessment state

Knowledge sources must preserve provenance and trust metadata. Knowledge ingestion must account for freshness, poisoning, source reliability, and evaluation.

The knowledge layer may contain:

- Vulnerability research
- Methodologies
- Payload knowledge
- Historical accepted findings
- Verification strategies
- Technology-specific intelligence
- Curated external data

A vector database or external knowledge service is not required at the initial stage. Storage technology is selected by workload.

---

# 29. Bounded Agentic Workflow

ARFA's future agentic behavior is a controlled workflow system, not an unrestricted autonomous attacker.

The conceptual loop is:

```text
Observe
   ↓
Understand
   ↓
Generate Candidate Actions
   ↓
Policy / Authorization Check
   ↓
Deterministic Planner
   ↓
Execute
   ↓
Verify
   ↓
Collect Evidence
   ↓
Update Obligations / State
   ↓
Choose Next Action
```

The loop is bounded by:

- Scope
- Authorization
- Capability grants
- Time
- Request count
- Rate
- Resource budget
- Destructive-action policy
- Approval requirements
- Stop conditions

AI may propose candidate actions, but policy and deterministic execution controls decide whether and how they run.

Workflow state must be persistable so execution can pause, resume, recover, and audit.

---

# 30. Safety and Destructive-Test Policy

Budgets alone are insufficient for operations that can change external state.

Actions must carry an explicit test intent where relevant, such as:

- Read-only
- State-changing
- Destructive
- Concurrency-sensitive
- Credential-changing
- Account-creation
- Transaction-signing

High-risk operations require explicit policy/approval according to assessment configuration.

This applies especially to:

- Account creation/deletion
- Credential changes
- Race testing
- Web3 transactions
- State-changing API requests
- Destructive external-tool actions
- Privileged plugin operations

---

# 31. Reporting and User Experience

ARFA is intended to become one coherent application rather than a collection of unrelated interfaces.

The UX should expose domain-adaptive workspaces such as:

- Assessments
- Attack Surface
- Application Map
- Traffic / Proxy
- Browser
- Scanner
- Findings
- Evidence
- Repeater
- Intruder
- Attack Chains
- History / Regression
- Workflows
- Knowledge
- Settings / Extensions

The user should be able to move between discovery, traffic, browser, scanner, findings, and evidence without losing assessment context.

The interface must clearly distinguish:

- Verified findings
- Unverified signals
- Inconclusive results
- Incomplete assessment
- Blocked/challenged targets
- Coverage gaps
- AI suggestions

GUI technology is an implementation decision. The architecture does not require a specific frontend framework.

---

# 32. Data Architecture

The initial platform should remain local-first and operationally simple.

The authoritative data layer must support:

- Assessments
- Runs
- Actions
- Assets
- Relationships
- Obligations/outcomes
- Findings
- Evidence references
- Verification records
- Identities/session references
- Workflow checkpoints
- Audit records

SQLite remains suitable for the local-first stage where workload permits it. Persistence must be behind repository boundaries so a future PostgreSQL/team deployment does not require rewriting domain logic.

Evidence artifacts should be stored separately from transactional records when appropriate, using content-addressed storage and controlled retention.

The architecture does **not** require Kafka, NATS, Temporal, ClickHouse, Neo4j, or a separate vector database at the initial stage. Each requires a measured scaling or capability trigger.

---

# 33. Eventing and Jobs

Durable job state is required for long-running work, but a distributed broker is not automatically required.

The initial implementation may use:

- Persisted job records
- Transactional state transitions
- Local worker pools
- Durable checkpoints
- Outbox-style records where needed

A message broker or workflow engine may be introduced later when demonstrated requirements include distributed workers, high concurrency, cross-host scheduling, or stronger delivery guarantees.

The logical job contract must remain stable across deployment models.

---

# 34. Search and Query

As ARFA grows, users must be able to search across the assessment knowledge space.

The architecture should support search across:

- Assets
- Endpoints
- Requests/responses
- Findings
- Evidence metadata
- Technologies
- Identities
- Runs
- Attack chains
- Knowledge
- Workflows

A global search/query language may evolve from local relational full-text search before introducing specialized search infrastructure.

---

# 35. Provenance and Auditability

Every important security fact must have provenance sufficient to answer:

- What produced it?
- Which assessment/run?
- Which action?
- Which engine/plugin/tool?
- Which version?
- Which identity/session context?
- Which verification strategy?
- Which evidence?
- When?
- Under which policy?

AI results must have provider/model/version/request provenance where applicable.

External tools and plugins must be identifiable in evidence and audit records.

Future integrity mechanisms may include hash chains or signed assessment history where required.

---

# 36. Deployment Evolution

ARFA evolves through deployment levels without changing its conceptual contracts.

```text
Local
  ↓
Team / Shared
  ↓
Enterprise / Distributed
```

### Local

- Single application
- Local SQLite
- Local artifact store
- Embedded workers
- Selected process isolation

### Team

May add:

- PostgreSQL
- Shared object storage
- Remote execution workers
- Authentication/RBAC
- Centralized audit
- Shared scheduling

### Enterprise

May add, when justified:

- Distributed job infrastructure
- Message brokers
- Analytical stores
- Dedicated search
- Distributed artifact storage
- Strong multi-tenant isolation
- High-availability control plane

No infrastructure component becomes mandatory merely because it is common in large systems.

---

# 37. Technology Selection Policy

Architecture defines capabilities and contracts before locking implementation technologies.

Technology choices must be evaluated using:

- Security
- Protocol coverage
- Reliability
- Reproducibility
- Performance
- Isolation
- Developer productivity
- Ecosystem maturity
- Operational complexity
- Local/offline usability
- Migration cost

Go and Python are existing strategic assets, not an absolute prohibition against other technologies.

Rust, TypeScript, Java, Kotlin, C/C++, or other technologies may be introduced when a documented workload or security requirement justifies them.

No performance claim may be treated as an architectural fact without representative benchmarking.

---

# 38. Compatibility and Versioning

Existing contracts must remain readable and compatible by default.

`arfa.scan/v1` remains a supported historical contract.

The platform should prefer additive evolution where possible. A new universal envelope containing every future domain is not required.

Future cross-domain contracts should remain small and composable around concepts such as:

- Assessment
- Action
- Observation
- Verification
- Evidence reference
- Finding

A breaking semantic change requires:

1. Explicit architectural decision
2. Versioning
3. Migration strategy
4. Compatibility period where practical
5. Regression coverage
6. Documentation update

---

# 39. Current Code Evolution Rules

Existing verified packages are preserved by default.

Current components such as the crawler, detectors, scanner, HTTP client, rate limiter, payload system, CLI, and report layer must not be broadly rewritten merely to match the future architecture.

The architecture is implemented through adapters, wrappers, additive contracts, and incremental evolution wherever practical.

A component may be redesigned only when:

- The existing boundary cannot support a required capability
- The limitation is demonstrated
- Alternatives were considered
- Compatibility/migration is defined
- The change is explicitly approved

---

# 40. Protected Foundation

The following areas remain protected unless a scheduled change explicitly requires them:

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

`pkg/report` is protected from unrelated redesign and may receive only the minimum integration required by a scheduled capability.

Protected does not mean permanently immutable. It means changes require technical necessity and explicit phase scope.

---

# 41. Extension of the Vulnerability Framework

ARFA must support the broadest practical range of known and emerging vulnerability classes across supported technologies.

The vulnerability framework must therefore separate:

- Vulnerability definition
- Detection logic
- Payload knowledge
- Execution strategy
- Verification strategy
- Evidence requirements
- Technology applicability
- Protocol applicability
- Risk metadata
- Remediation/description metadata

Adding a new vulnerability class should not require redesigning the assessment core.

The same principle applies to new payloads, protocols, browser checks, mobile checks, Web3 checks, and verification methods.

---

# 42. Attack Chains and Correlation

Attack chains are evidence-backed correlations, not speculative narratives.

A chain may connect:

```text
Asset
  ↓
Observation / Finding
  ↓
Relationship
  ↓
Follow-up Evidence
  ↓
Verified Finding
```

Attack-chain relationships and evidence references must preserve provenance.

AI may propose candidate chains, but authoritative chains used in reporting must be grounded in available evidence and deterministic relationships.

---

# 43. Continuous Assessment

Continuous assessment reuses the Assessment/Run model.

A continuous workflow may:

- Discover changes
- Compare attack surface
- Schedule incremental tests
- Re-run relevant obligations
- Compare findings
- Track regressions
- Notify users

Continuous assessment is not a separate scanner architecture. It is a scheduling and workflow layer over the same Control Plane and execution contracts.

---

# 44. External Input and Observation Boundaries

External formats must remain adapters rather than becoming core data models.

Examples include:

- HAR
- Burp traffic/results
- mitmproxy traffic
- Nmap output
- Nuclei output
- OpenAPI
- GraphQL schemas
- Mobile artifacts
- Web3 analysis output
- OAST callbacks

Adapters normalize external observations into ARFA contracts while preserving original provenance.

Differential observations are analysis signals until verification establishes their meaning.

---

# 45. Security of Plugins, Tools, and AI

Every non-core execution capability is a potential trust boundary.

Security controls must include, as appropriate:

- Capability manifests
- Least privilege
- Network mediation
- Artifact access policy
- Secret access policy
- Resource quotas
- Timeouts
- Process isolation
- Revocation
- Version pinning
- Audit records
- Trust levels
- Assessment isolation

Plugin signing or process isolation alone is not sufficient to establish authorization safety.

---

# 46. Architectural Decision Summary

The following decisions are fixed architectural direction unless explicitly revisited through a new decision record.

| # | Decision |
|---|---|
| 1 | ARFA uses Control Plane + constrained Execution Agents + Intelligence Layer. |
| 2 | Initial deployment is local-first/modular; logical separation precedes distributed deployment. |
| 3 | The Control Plane owns assessment policy, scheduling, state, coverage obligations, verification authority, evidence references, findings, and audit. |
| 4 | Domain engines integrate through an execution contract and may use domain-native implementations. |
| 5 | Authoritative findings require the verification boundary; execution engines, AI, and external tools do not bypass it. |
| 6 | Observation, Evidence, Verification, and Finding remain distinct concepts. |
| 7 | Test Obligations + Outcomes are the long-term coverage source of truth; coverage matrices are projections. |
| 8 | Readiness is independent from coverage and must be reported honestly. |
| 9 | Assessment contains Runs and supports history, regression, and continuous assessment. |
| 10 | Assets and relationships use a relational model initially; graph infrastructure is not mandatory. |
| 11 | Scope, capability, and egress controls apply to every execution boundary. |
| 12 | Identity, session, credential, device, and wallet contexts are first-class and secrets stay behind a vault boundary. |
| 13 | Traffic/interception is a core capability; implementation technology is benchmark-driven, not preselected. |
| 14 | Browser is a first-class execution/discovery/verification engine. |
| 15 | Mobile is a domain-native execution engine behind common contracts. |
| 16 | Web3 is a domain-native execution engine with simulation/trace/state-diff support. |
| 17 | OAST is a first-class verification capability with isolation and delayed-callback handling. |
| 18 | Plugins use stable contracts, explicit capabilities, lifecycle management, and controlled runtimes. |
| 19 | AI/knowledge/agentic workflows are bounded and cannot override authorization, policy, or authoritative verification. |
| 20 | Data/recovery/evidence custody are first-class; distributed infrastructure is introduced only at demonstrated scaling boundaries. |

These decisions are architectural constraints for future phases. They do not imply immediate implementation of every capability.

---

# 47. Architecture-to-Phase Rule

The architecture defines the complete destination.

The roadmap determines ordering.

A phase defines the bounded work currently authorized for implementation.

Therefore:

```text
Architecture
     ↓
Capability / Dependency Analysis
     ↓
Roadmap
     ↓
Phase
     ↓
Technical Decisions
     ↓
Implementation
     ↓
Validation
     ↓
Freeze / Review
```

No implementation phase may invent a conflicting architecture because a detail was not anticipated. If an implementation discovers a genuine architectural gap, it must stop at the relevant boundary and produce an explicit architectural decision before proceeding.

---

# 48. Rules for AI Implementers

Claude, Codex, Gemini, and other implementation assistants must:

1. Read this architecture and the current `ARFA_MASTER_CONTEXT.md` before substantial work.
2. Read the actual source files relevant to the task.
3. Treat repository code as the source of truth for current implementation.
4. Treat this document as the source of truth for architectural direction and boundaries.
5. Implement only the current phase/TD scope.
6. Preserve closed work unless an approved architectural change explicitly requires evolution.
7. Never invent missing files, interfaces, capabilities, or test results.
8. Stop and report if an architectural prerequisite is missing rather than guessing.
9. Use the smallest necessary change.
10. Do not introduce infrastructure merely because the architecture mentions it as a possible future option.
11. Do not allow AI output to bypass deterministic authorization, scope, budget, verification, or evidence rules.
12. Return a reviewable patch and exact validation results.

---

# 49. Phase Discipline

Do not:

- Rewrite the verified foundation without justification.
- Replace deterministic planning with an unrestricted LLM.
- Treat architecture descriptions as proof of implementation.
- Add unrelated refactoring to a phase.
- Introduce distributed infrastructure prematurely.
- Create hidden scope expansion through discovery or plugins.
- Store secrets in findings or normal evidence.
- Treat an unverified tool/AI claim as an authoritative finding.

Do:

- Inspect the actual repository.
- Confirm dependencies before implementation.
- Keep contracts explicit.
- Add tests with behavior changes.
- Validate locally.
- Review diffs.
- Preserve compatibility.
- Record architectural changes explicitly.

---

# 50. Source-of-Truth Hierarchy

For implementation facts:

1. **Actual repository source code** — what is implemented and verified.
2. **`ARFA_MASTER_CONTEXT.md`** — current project state, milestones, phases, and operational context.
3. **`ARCHITECTURE.md`** — complete architectural direction and boundaries.
4. **`PLATFORM_STRATEGY.md`** — long-term strategy, principles, intake, and ecosystem direction.

No document may claim that a capability exists when the repository does not verify it.

If an architectural requirement conflicts with the current implementation, the implementation does not become magically correct; the conflict must be handled through the phase/decision process.

---

# 51. Validation Requirements

Every implementation phase must use the relevant validation set.

For Go changes:

```bash
gofmt -w <changed-go-files>
go build ./...
go vet ./...
go test ./...
```

For concurrency-sensitive changes:

```bash
go test ./... -race
```

Python changes require the relevant Python test suite.

End-to-end behavior should be validated for capabilities that cross subsystem boundaries.

A change is not complete because it compiles. The behavior, contracts, evidence, security boundaries, and regression surface must be validated.

---

# 52. Final Architectural Statement

ARFA is not architected as a collection of independent scanners.

It is architected as a unified authorized assessment platform with:

- A policy-owning Control Plane
- Constrained domain execution engines
- A deterministic verification/evidence truth path
- A unified asset and assessment model
- Sparse test obligations and outcomes
- First-class readiness
- First-class identity and security boundaries
- Traffic and Browser as core capabilities
- Native Mobile and Web3 engines
- OAST and race execution patterns
- External-tool and plugin integration
- AI, knowledge, correlation, and bounded agentic workflows
- Durable evidence, provenance, history, and recovery
- A local-first path to team and enterprise scale

The architecture deliberately defines **where ARFA must be able to go without forcing a premature decision about every implementation technology**.

The next phase must be derived from this architecture rather than used to discover the architecture accidentally.

> **Define the destination first. Implement it incrementally. Preserve the verified truth path. Expand capability without sacrificing authorization, evidence, verification, or control.**
