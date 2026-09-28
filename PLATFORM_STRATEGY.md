# ARFA VAPT — Platform Strategy

> **Status:** Strategic reference — long-term product direction, platform principles, ecosystem strategy, and capability intake.
> **Scope:** Defines how ARFA grows as a platform. It does not claim that future capabilities are implemented today.
> **Relationship to other sources:**
> - `ARCHITECTURE.md` — authoritative architectural direction and boundaries.
> - `ARFA_MASTER_CONTEXT.md` — authoritative current project state, completed work, active phase, and roadmap execution state.
> - Repository `main` / actual source code — authoritative source for implemented behavior.
> - This document — long-term strategy, platform principles, extension/integration strategy, and intake rules.

---

## 1. Strategy Statement

ARFA VAPT is designed as a **unified authorized assessment and security-intelligence platform**, not as a scanner that accumulates unrelated features.

The strategic principle is:

> **Design for the complete product. Implement incrementally. Preserve the verified truth path. Expand capability without sacrificing authorization, evidence, verification, or control.**

This creates two simultaneous obligations:

1. **Think broadly:** the platform must be able to grow into Web, API, Browser, Mobile, Web3, Traffic, external reconnaissance, OAST, AI-assisted analysis, attack-chain correlation, reporting, continuous assessment, integrations, and extensibility.
2. **Build narrowly:** each phase must have a bounded scope, explicit contracts, tests, review, and a clean merge/freeze point.

A large strategy is not permission to implement everything at once.
A small current implementation is not permission to design tomorrow's capabilities as dead ends.

---

## 2. Strategy vs Architecture vs Roadmap vs Phase vs Code

These are different layers and must not be mixed.

```text
ARCHITECTURE
Complete product structure, boundaries, contracts, and invariants
        ↓
PLATFORM STRATEGY
Long-term growth principles, ecosystem, extensions, integrations, intake
        ↓
ROADMAP
Current ordering of capabilities and implementation priorities
        ↓
PHASE / TD
One bounded implementation unit
        ↓
CODE
What is actually implemented and verified
```

### Rules

- `ARCHITECTURE.md` defines the architectural destination and boundaries.
- `PLATFORM_STRATEGY.md` defines how the platform should evolve without losing coherence.
- `ARFA_MASTER_CONTEXT.md` defines the current operational state and roadmap.
- A phase/TD defines only the work explicitly authorized for that unit.
- The repository defines what actually exists.
- A capability appearing in strategy or architecture is **not** evidence that it is implemented.
- A roadmap item is **not** an active implementation scope until a phase/TD is opened.
- A phase must not be used to discover fundamental architecture accidentally. If implementation reveals a genuine architectural conflict, stop and record the decision before expanding scope.

---

## 3. Platform Growth Principles

### 3.1 No self-imposed ceiling

ARFA should not reject a useful capability merely because it is larger than today's codebase, team, or tooling.

Potential capabilities may include:

- Web and API assessment
- Browser-assisted assessment
- Traffic interception and manipulation
- Mobile Android/iOS assessment
- Web3 and dApp assessment
- External attack-surface discovery
- OAST / out-of-band verification
- Race and concurrency testing
- Authentication and authorization testing
- AI-assisted analysis and correlation
- Attack-chain construction
- Continuous assessment
- External security-tool integrations
- Extensions/plugins
- Knowledge and methodology services
- Enterprise reporting, governance, and auditability

The architectural question is whether the capability can be integrated while preserving the platform's invariants — not whether the capability is too ambitious.

### 3.2 No self-imposed rush

The platform is built incrementally.

A capability may be accepted into the long-term architecture without being placed on the current roadmap. A roadmap item may remain unscheduled until prerequisites are ready.

### 3.3 Preserve before replacing

Existing verified behavior is preserved by default.

A replacement is justified only when it provides a measurable architectural or operational advantage and the migration path is explicit.

### 3.4 Reuse contracts, not accidental implementations

Future components should reuse stable contracts and domain semantics where appropriate, not copy internal implementation details merely because they already exist.

### 3.5 Additive growth is preferred

New capability should normally be additive:

- new execution engines,
- new adapters,
- new verification strategies,
- new evidence processors,
- new integrations,
- new extensions,
- new UI workspaces,
- new domain models where genuinely required.

Core contract changes remain possible, but must be deliberate, versioned, compatible-by-default, and regression-tested.

---

## 4. The Platform Shape

ARFA's strategic shape follows the architectural model in `ARCHITECTURE.md`:

```text
                 ┌──────────────────────────────┐
                 │        User / API / UI       │
                 └──────────────┬───────────────┘
                                ↓
                 ┌──────────────────────────────┐
                 │        Assessment Control     │
                 │ scope • auth • policy • run   │
                 │ budget • lifecycle • recovery │
                 └──────────────┬───────────────┘
                                ↓
        ┌───────────────────────┴───────────────────────┐
        │                                               │
┌───────▼────────┐                              ┌───────▼────────┐
│ Execution       │                              │ Intelligence   │
│ Engines         │                              │ Layer          │
│ Web/API         │                              │ AI / Knowledge │
│ Browser         │                              │ Correlation    │
│ Mobile          │                              │ Risk / Chains  │
│ Web3            │                              │ Planning       │
│ Traffic/OAST    │                              └────────────────┘
│ Recon/Tools     │
└───────┬────────┘
        ↓
 Observation → Verification → Evidence → Finding
        ↓
 Correlation → Attack Chain → Risk → Report / Next Action
```

The strategic consequence is important:

> ARFA is not required to force every capability into the original Go scanner.

The platform can grow through domain-native engines and constrained execution agents while preserving one assessment/control model and one authoritative truth path.

---

## 5. Truth, Evidence, and AI

### 5.1 Deterministic truth path

The platform's central security invariant is:

```text
Observation
    ↓
Hypothesis / Candidate Test
    ↓
Bounded Execution
    ↓
Verification
    ↓
Evidence
    ↓
Finding
```

AI, external tools, heuristics, differential analysis, and knowledge systems may contribute observations, hypotheses, prioritization, or analysis.

They do **not** bypass verification and evidence requirements to create authoritative findings.

### 5.2 Evidence is a platform asset

Evidence must be:

- attributable to an authorized assessment/action,
- bounded and appropriately redacted,
- linked to the observation and verification that produced it,
- durable enough for audit and reporting,
- protected from accidental secret leakage,
- traceable to its producer and relevant tool/version.

### 5.3 Provenance

The platform should preserve provenance across:

- native detectors,
- domain execution engines,
- extensions,
- external tools,
- browser actions,
- traffic observations,
- OAST interactions,
- AI analysis,
- correlation and attack-chain construction.

Provenance answers: **what happened, who/what produced it, under which assessment/action, and what evidence supports the conclusion?**

### 5.4 AI boundary

AI is an intelligence layer, not the source of security truth.

AI may:

- analyze observations,
- correlate findings,
- summarize evidence,
- identify candidate relationships,
- propose next actions,
- prioritize work,
- assist with attack-chain reasoning,
- use approved knowledge sources.

AI must not silently:

- bypass authorization,
- expand scope,
- convert an unsupported hypothesis into a confirmed finding,
- discard contradictory evidence,
- hide tool failures,
- fabricate evidence or execution history.

Any bounded agentic workflow must remain under the control-plane policies, budgets, action lifecycle, and evidence model.

---

## 6. Core Contract Strategy

The platform should maintain a **small set of composable contracts** rather than one universal data object that accumulates every future feature.

Important contract families include:

| Contract family | Strategic role |
|---|---|
| Authorization / Scope | Defines what the platform is allowed to touch. |
| Assessment / Run | Defines the bounded assessment lifecycle. |
| Action / Execution | Gives each active operation identity, policy, budget, and recovery semantics. |
| Observation | Normalizes what an engine, tool, browser, or adapter observed. |
| Verification | Records how a hypothesis was tested and with what result. |
| Evidence | Preserves bounded proof and provenance. |
| Finding | Defines the authoritative security result. |
| Coverage / Test Obligation | Tracks what was attempted, what was not, and why. |
| Readiness | Separately describes whether a target was meaningfully assessable. |
| Asset / Relationship | Represents the attack surface and its relationships. |
| Report / Output | Exposes stable reader-facing results. |
| Extension / Integration | Defines controlled capability contributions. |

The existing `arfa.scan/v1` boundary remains readable and compatible. Future growth should prefer additive/composable records and versioned contracts over an uncontrolled universal envelope.

---

## 7. Extension Strategy

### 7.1 Extension is a capability mechanism, not the only capability mechanism

Extensions are appropriate when a capability can be safely added through a stable contract.

Some capabilities require first-class platform ownership because they define major execution, lifecycle, security, or data semantics. Examples include:

- assessment control,
- authorization/scope enforcement,
- core evidence custody,
- identity/session security boundaries,
- traffic infrastructure,
- browser assessment engine,
- major Mobile/Web3 execution engines.

Therefore:

> **Use extensions where extension semantics fit. Use native platform/domain components where first-class semantics are required.**

### 7.2 Multi-capability extensions

An extension may provide one or more capabilities, such as:

- Detector
- Verifier
- Analyzer
- Discovery/Crawler
- Payload provider
- Evidence processor
- Correlation capability
- Risk capability
- Integration/Bridge
- Language/framework intelligence

The extension declares its capabilities instead of being treated as merely a detector plugin.

### 7.3 Extension lifecycle

The strategic lifecycle is:

```text
Discover → Register → Validate → Enable → Configure → Run
       → Disable → Upgrade → Remove
```

Every transition is explicit and auditable.

### 7.4 Manifest

The extension manifest should declare at minimum:

- `name`
- `id`
- `version`
- `extension_api_version`
- `core_compatibility`
- capabilities
- dependencies
- configuration schema
- supported targets/frameworks
- security/trust metadata
- required permissions/capabilities

### 7.5 Trust boundary

An extension must not automatically receive access to:

- target traffic,
- filesystem,
- network,
- credentials,
- session material,
- secrets,
- privileged execution.

Access must be declared, mediated by policy, bounded, and auditable.

The extension runtime mechanism remains an implementation decision for the phase that builds it. The strategic contract must not depend on a single loading technology.

### 7.6 Failure isolation

A failing extension should not corrupt the assessment or bring down the control plane.

Failures should be represented as bounded execution outcomes and should not be silently converted into success or false security conclusions.

---

## 8. Integration Strategy

ARFA is designed to coexist with the security-tool ecosystem.

### 8.1 External tools are capability sources

External tools can contribute:

- observations,
- requests/responses,
- findings,
- evidence,
- discovery data,
- specialized scanning,
- browser/traffic capabilities,
- protocol support.

Their output enters ARFA through controlled adapters and remains an observation/signal until it satisfies ARFA's own normalization, verification, evidence, and provenance requirements.

### 8.2 Bidirectional integration

The integration boundary should support bidirectional workflows where useful, including:

```text
ARFA ↔ Burp Suite
ARFA ↔ ZAP
ARFA ↔ Nuclei
ARFA ↔ other specialized tools
```

Potential exchanged objects include:

- targets and scope,
- requests/responses,
- traffic,
- findings,
- evidence,
- scan/assessment context.

Exact integration scope is determined during capability intake and implementation phases.

### 8.3 Traffic adapter boundary

HAR, Burp, mitmproxy/proxy traffic, captured requests, and similar sources should enter through adapters.

External traffic formats must not dictate ARFA's core data model.

### 8.4 No artificial tool exclusion

A tool is not excluded merely because it is powerful or overlaps with ARFA.

The decision is based on:

- capability value,
- integration quality,
- security boundary,
- provenance,
- operational cost,
- maintainability,
- user workflow.

---

## 9. Traffic, Browser, and Domain Engines

These are strategic first-class capabilities, not optional decorations around the original scanner.

### 9.1 Traffic

The traffic subsystem should support, as the architecture matures:

- interception/proxying,
- HTTPS handling,
- request/response inspection,
- traffic history,
- site/application mapping,
- repeater workflows,
- intruder-style controlled iteration,
- session/auth context,
- WebSocket/SSE/GraphQL-aware traffic where applicable,
- traffic-to-finding/evidence linkage,
- scanner ↔ traffic interoperability.

### 9.2 Internal Browser

The internal browser is an assessment engine, not merely a UI automation helper.

It should eventually support:

- JavaScript execution,
- SPA discovery,
- browser-state/session handling,
- DOM and network observations,
- dynamic route/API discovery,
- browser-assisted verification,
- visual/screenshot evidence where justified,
- integration with the traffic subsystem.

The browser complements deterministic discovery; it does not invalidate it.

### 9.3 Mobile

Mobile assessment should be a domain-native capability covering appropriate Android/iOS workflows, artifacts, runtime observations, network behavior, and evidence.

The platform should not force mobile semantics into HTTP-only models.

### 9.4 Web3

Web3 assessment should support the relevant layers independently and together:

- smart contracts,
- ABI/interfaces,
- transaction behavior,
- wallets and signing boundaries,
- dApps,
- RPC interactions,
- chain/deployment metadata,
- authorization and business-logic analysis.

The Web3 engine must retain the same platform-level authorization, evidence, provenance, and verification invariants.

---

## 10. Reconnaissance and Attack-Surface Strategy

ARFA should grow from a target-centric scanner into an attack-surface-aware assessment platform.

Potential asset types include:

- domains,
- subdomains,
- IPs,
- ports,
- services,
- certificates,
- applications,
- APIs,
- endpoints,
- parameters,
- mobile artifacts,
- Web3 contracts/deployments,
- identities/principals.

The asset model should support relationships without forcing a graph database prematurely.

### External attack surface

External reconnaissance may include, within explicit authorization/scope:

- domain discovery,
- DNS observations,
- certificate relationships,
- exposed services,
- application identification,
- endpoint/API discovery,
- technology/framework observations.

Recon findings are observations until they are normalized and, where required, verified.

---

## 11. Readiness, Coverage, and Honest Results

The strategy explicitly separates three questions:

1. **Readiness:** Was the target meaningfully assessable?
2. **Coverage:** What test obligations were attempted or completed?
3. **Findings:** What security conclusions were actually verified?

These must not be collapsed into one metric.

For example:

```text
Transport reachable
        ≠
Application assessable
        ≠
Full coverage
        ≠
No vulnerabilities
```

This is essential for reporting and user trust.

A scan that encounters a login barrier, anti-bot challenge, unsupported application behavior, broken session state, or another material limitation must expose that limitation rather than presenting a clean zero-result scan as equivalent to a complete assessment.

---

## 12. Identity, Session, and Secrets Strategy

Authorized identities are a platform capability, not merely detector configuration.

The future identity/session layer should support, where scope permits:

- authorized test-account provisioning,
- secure credential/secret storage,
- session lifecycle management,
- reusable authorized sessions,
- multiple principals for authorization testing,
- safe identity references in evidence and findings,
- rotation, disablement, and deletion.

Secrets must remain behind a dedicated security boundary and must not leak into normal findings, reports, scan history, or evidence.

The platform should integrate identity references with authorization testing and the existing `AuthContext` model rather than replacing domain semantics already established in the core.

---

## 13. OAST and Out-of-Band Strategy

OAST is a distinct verification capability.

The platform should support:

- unique interaction tokens,
- correlation to originating actions,
- interaction timestamps,
- delayed callbacks,
- expiry,
- cancellation,
- isolation between assessments,
- replay/analysis where appropriate.

An OAST callback is an observation. It becomes security evidence only after the verification layer establishes the relevant relationship to the authorized action and hypothesis.

---

## 14. Race and Stateful Testing Strategy

Race/concurrency testing is an execution pattern rather than a single vulnerability detector.

The platform should eventually support controlled:

- parallel requests,
- synchronized request release,
- repeated state transitions,
- ordering variations,
- bounded concurrency windows,
- state comparison and verification.

Race testing must have explicit test intent and state/authorization boundaries. A high request count or budget is not itself sufficient authorization for destructive behavior.

---

## 15. Safety and Authorization Strategy

Authorization is a platform invariant.

Every active execution path — including engines, extensions, browser actions, integrations, plugins, and future agents — must operate inside an explicit assessment policy.

The policy must ultimately cover:

- target scope,
- allowed protocols/actions,
- authorization acknowledgement,
- credentials/identity permissions,
- destructive-test permissions,
- egress restrictions,
- redirect handling,
- DNS/rebinding considerations,
- resource/time budgets,
- cancellation,
- auditability.

### Destructive operations

A budget does not replace permission.

Potentially destructive/state-changing operations require explicit test intent and appropriate policy approval in addition to ordinary execution limits.

### Agentic execution

An agent must not be able to widen its own scope merely because its reasoning suggests another target or action.

Agent proposals pass through the same policy and execution boundaries as deterministic actions.

---

## 16. Data and Persistence Strategy

The platform should distinguish between different classes of durable data:

### Authoritative operational state

Examples:

- assessments,
- runs,
- actions,
- assets,
- findings,
- coverage/test obligations,
- readiness,
- identities/references,
- configuration.

### Evidence and artifacts

Examples:

- request/response evidence,
- screenshots,
- captured traffic fragments,
- OAST interaction records,
- mobile artifacts,
- Web3 artifacts.

Evidence should have controlled retention and provenance.

### Derived intelligence

Examples:

- correlations,
- attack chains,
- risk calculations,
- AI analyses,
- knowledge retrieval results.

Derived intelligence must remain distinguishable from authoritative execution truth.

The initial deployment may remain local-first and simple. Storage technology should evolve when measured requirements justify it rather than because a large product is expected eventually.

---

## 17. Search and Knowledge Strategy

A mature ARFA installation should provide unified search across the information users are authorized to access, potentially including:

- assets,
- endpoints,
- traffic,
- findings,
- evidence,
- assessments,
- identities/references,
- attack chains,
- reports,
- knowledge objects.

### Knowledge layer

Future knowledge capabilities may include:

- security methodologies,
- vulnerability research,
- curated advisories,
- public vulnerability intelligence,
- internal methodology,
- reusable investigation patterns,
- verified lessons from prior assessments.

Knowledge is a reasoning aid, not evidence.

Knowledge retrieval must preserve source provenance and must not silently convert external claims into ARFA findings.

---

## 18. Continuous Assessment Strategy

ARFA should eventually support both bounded assessments and recurring/continuous assessment.

Continuous workflows may include:

- scheduled reconnaissance,
- change detection,
- new endpoint discovery,
- differential security testing,
- regression checks,
- re-verification of known findings,
- attack-surface drift detection.

The same authorization and scope model applies to every recurring execution. A previous authorization does not implicitly authorize a new target or a newly destructive action.

Continuous execution also requires:

- idempotency,
- recovery,
- action identity,
- cancellation,
- retention policy,
- auditability,
- bounded resource consumption.

---

## 19. Reporting and Product Experience Strategy

The UI should be one coherent application with domain-adaptive workspaces rather than a collection of disconnected tools.

The strategic mental model is:

```text
Targets / Assets
      ↓
Assessment / Scope
      ↓
Discovery / Mapping
      ↓
Traffic / Browser / Domain Engines
      ↓
Testing / Verification
      ↓
Evidence / Findings
      ↓
Correlation / Attack Chains / Risk
      ↓
Reports / History / Next Actions
```

The platform should expose familiar workflows where they improve usability — such as proxy/history, repeater, intruder-style iteration, site mapping, and dashboards — without making the product a copy of any one existing tool.

Reporting should make the following visible:

- what was tested,
- what was not tested,
- readiness limitations,
- coverage,
- findings,
- evidence,
- confidence,
- provenance,
- tool/engine participation,
- relevant next actions.

---

## 20. Plugin and Extension Security Strategy

The plugin/extension system is itself an attack surface.

The platform should assume that extensions may contain bugs or may be untrusted.

Required strategic controls include:

- explicit capabilities,
- permission mediation,
- resource quotas,
- network restrictions,
- filesystem restrictions,
- secret restrictions,
- audit logs,
- version/compatibility checks,
- revocation/disablement,
- failure isolation,
- safe upgrade/removal.

Signing may improve trust decisions, but signing alone is not a security boundary.

---

## 21. Baselines, KPIs, and Engineering Evidence

Meaningful platform changes should be measurable when a relevant metric exists.

Possible metrics include:

- scan duration,
- throughput,
- readiness rate,
- coverage,
- verification coverage,
- false-positive rate,
- reproducibility,
- evidence completeness,
- resource usage,
- recovery success,
- integration reliability.

A metric without a reproducible measurement method is not sufficient evidence for a performance or quality claim.

Metrics are selected per capability/phase rather than frozen as one global scorecard.

---

## 22. Learning From Existing Security Tools

ARFA should learn from mature security tooling without treating any tool as an architectural template.

Useful mental models include:

- proxy/interception workflows,
- request history,
- repeater workflows,
- intruder-style controlled iteration,
- site/application mapping,
- browser-assisted testing,
- scanner/verifier separation,
- rich evidence/reporting,
- extension ecosystems.

The goal is not feature imitation.

The goal is to understand proven workflows and incorporate them into ARFA's own authorization, execution, evidence, and verification model.

---


---

## 23. Cross-Cutting Architectural Coverage

The strategy must remain aligned with the architecture across the major platform surfaces. The following map is intentional:

| Architectural area | Strategic position |
|---|---|
| Control Plane | Owns policy, scope, assessment lifecycle, budgets, recovery, and governance. |
| Execution Contract | Every active operation has bounded identity, authorization, inputs, outputs, and outcome semantics. |
| HTTP / API Engine | Remains a first-class deterministic execution domain and the current foundation is preserved rather than discarded. |
| Traffic / Interception | Becomes a shared assessment capability connecting browser, scanner, repeater-style workflows, and evidence. |
| Browser | First-class assessment engine for dynamic applications and browser-state-dependent behavior. |
| Mobile | Domain-native engine for Android/iOS assessment. |
| Web3 | Domain-native engine for contracts, dApps, wallets, RPC, and transaction behavior. |
| OAST | Isolated out-of-band observation/correlation capability feeding verification. |
| Race / Concurrency | Controlled execution pattern with explicit state and test intent. |
| External Tools | Adapter boundary; external output is observation/signal until normalized and verified. |
| Plugins | Capability-based, permission-mediated, resource-bounded, auditable extension boundary. |
| AI / Knowledge | Intelligence layer that assists analysis without becoming authoritative security truth. |
| Agentic Workflow | Bounded proposal → policy check → execution → observation → verification loop. |
| Reporting / UX | One coherent application exposing readiness, coverage, findings, evidence, provenance, and next actions. |
| Data | Separates authoritative state, evidence/artifacts, and derived intelligence. |
| Eventing / Jobs | Supports bounded asynchronous work and future scale without making a broker mandatory today. |
| Search | Evolves toward unified authorized search across assets, traffic, findings, evidence, assessments, and knowledge. |
| Provenance / Audit | Preserves who/what acted, what happened, and how conclusions were derived. |
| Deployment | Local-first initially; team/enterprise scale introduced when requirements justify it. |
| Vulnerability Framework | New classes extend the deterministic detection/verification/evidence path without redesigning the platform core. |
| Attack Chains / Correlation | Derived from evidence-backed findings and relationships; not an independent source of truth. |
| Continuous Assessment | Reuses the same authorization, action, recovery, evidence, and audit controls as bounded assessments. |

This table is a strategy cross-check, not an implementation checklist. A capability remains unimplemented until the repository and current-state documentation say otherwise.

---

## 24. HTTP/API and Vulnerability-Framework Growth

The current HTTP/API scanner remains a foundational execution domain.

Future HTTP/API expansion may include, as justified by the roadmap:

- richer request bodies and encodings,
- multipart/file upload,
- cookies and session-aware execution,
- JSON and structured request manipulation,
- GraphQL,
- WebSocket/SSE,
- gRPC/Protobuf,
- OAuth/OIDC/JWT-aware workflows,
- webhook and callback analysis,
- differential and stateful testing.

These additions must not require replacing the deterministic core.

### Vulnerability framework

The platform must be able to add broad known and emerging vulnerability classes without creating a separate truth model for every detector.

New vulnerability capabilities should plug into the common pattern:

```text
Discovery / Observation
        ↓
Candidate / Test Obligation
        ↓
Bounded Execution
        ↓
Domain-specific Verification
        ↓
Evidence
        ↓
Finding
```

Domain-specific verification is allowed and often necessary. The authoritative status/evidence boundary remains platform-consistent.

---

## 25. Eventing, Jobs, and Recovery Strategy

Long-running assessments require an explicit job model even when the first implementation remains in-process.

The strategy supports:

- bounded jobs,
- action identity,
- idempotent execution where applicable,
- cancellation,
- retries with explicit semantics,
- partial failure representation,
- recovery after interruption,
- audit of job/action transitions.

A message broker or distributed workflow engine may become useful later, but the platform must not depend on one before measured requirements justify it.

---

## 26. Attack Chains, Correlation, and Risk

Correlation is a derived intelligence layer over authoritative observations/findings/evidence.

The platform may build relationships such as:

```text
Asset
  ↓
Finding
  ↓
Evidence
  ↓
Relationship
  ↓
Attack Chain
  ↓
Risk / Impact Context
```

An attack chain must remain evidence-backed and traceable to its constituent findings/observations.

AI may propose or explain relationships, but unsupported relationships must remain hypotheses rather than being presented as verified security facts.

---

## 27. External Input and Observation Boundaries

External data must enter through explicit boundaries.

Examples include:

- HAR,
- Burp/mitmproxy traffic,
- external scanner output,
- OAST interaction events,
- browser observations,
- mobile artifacts,
- Web3 metadata,
- differential-analysis inputs,
- future knowledge sources.

The strategic rule is:

> **Normalize at the boundary; do not let an external format become an accidental core model.**

External input is untrusted until validated against the relevant schema, scope, provenance, and execution context.

---

## 28. Technology Selection Strategy

The architecture intentionally separates **required capability** from **implementation technology**.

A future component may use Go, Python, Rust, TypeScript, Java/Kotlin, C/C++, a browser sidecar, a process boundary, or another technology when evidence supports the choice.

Technology selection should consider:

- correctness,
- security isolation,
- protocol support,
- performance,
- concurrency,
- ecosystem maturity,
- maintainability,
- operational complexity,
- testability,
- integration cost.

A language or framework must not be selected merely because it is fashionable or because another security tool uses it.

The existing Go/Python foundation remains an asset. Expansion is additive unless a measured requirement justifies otherwise.

---

## 29. Protected Foundation and Controlled Evolution

The existing deterministic scanner foundation contains valuable, verified behavior.

Future work should protect established components unless a scheduled change explicitly requires them.

The strategic rule is:

```text
Preserve verified behavior
        ↓
Extend through stable boundaries
        ↓
Change core only when justified
        ↓
Version / migrate / test
```

A conceptual architecture diagram is never a reason to rewrite working code.

When a core change is genuinely required, the change must identify:

- the contract affected,
- why extension/domain composition is insufficient,
- compatibility impact,
- migration strategy,
- regression coverage,
- rollback/recovery implications.

---

## 30. Provenance, Auditability, and Governance

A mature platform must be able to answer, after the fact:

- Who initiated the assessment?
- What scope and authorization applied?
- Which action executed?
- Which engine/tool/extension performed it?
- What was observed?
- What verification occurred?
- Which evidence supports the finding?
- What AI or correlation steps were applied?
- What was proposed versus actually executed?
- What failed, was skipped, or remained inconclusive?

Auditability is therefore not only a compliance feature. It is part of the platform's correctness model.

Sensitive material should be represented through safe references and controlled storage rather than copied into every downstream artifact.


---

## 31. Capability Intake Process

Every new capability enters through the same strategic intake.

```text
New capability proposed
        ↓
1. Mission / architecture fit?
        ↓
2. Core, domain engine, adapter, extension, or integration?
        ↓
3. Dependencies and prerequisites?
        ↓
4. Authorization / scope implications?
        ↓
5. Security / isolation implications?
        ↓
6. Evidence / provenance / verification impact?
        ↓
7. Data-model impact?
        ↓
8. Operational / recovery / resource implications?
        ↓
9. Roadmap placement?
        ↓
10. Bounded phase / TD?
```

### Intake rules

- A large capability is not rejected merely because it is large.
- An attractive capability is not implemented merely because it is attractive.
- A capability may enter architecture without entering the current roadmap.
- A roadmap item does not become implementation scope until a phase/TD is approved.
- No capability bypasses authorization, evidence, verification, or provenance requirements.
- If a capability requires a core contract change, the change is explicitly reviewed and versioned rather than smuggled into an unrelated phase.

### Intake decision record

A substantial decision should record:

- date,
- capability/decision,
- context,
- alternatives considered,
- decision,
- rationale,
- consequences,
- compatibility/migration implications,
- status: accepted / rejected / deferred.

This prevents settled decisions from being repeatedly re-litigated and makes reversals explicit.

---

## 32. Versioning and Compatibility Strategy

The platform should distinguish between:

### Internal implementation

May evolve freely within a bounded phase when behavior and contracts remain correct.

### Stable contracts

Require compatibility discipline.

Examples:

- `arfa.scan/v1`
- Finding fields
- evidence references
- verification semantics
- extension API contracts
- integration schemas.

### Versioning rules

- Prefer additive changes.
- Preserve existing readers where practical.
- Version breaking changes explicitly.
- Provide migration paths for durable data.
- Deprecate before removal where practical.
- Never silently reinterpret an old field with a materially different meaning.

---

## 33. Deployment and Scale Strategy

ARFA should evolve from a local-first deployment toward team/enterprise deployment without requiring an architectural rewrite.

### Early posture

- modular monolith / embedded workers where practical,
- local persistence,
- explicit boundaries,
- simple operational dependencies.

### Later posture

Where measured requirements justify it, components may become:

- separate workers,
- remote execution agents,
- shared persistence services,
- dedicated browser/traffic services,
- queue/event infrastructure,
- team/enterprise control-plane services.

Technology choices such as brokers, graph databases, analytical stores, or distributed workflow systems are **not strategic requirements by themselves**. They are implementation options evaluated against measured scale and reliability needs.

---

## 34. Rules for AI Implementers

Claude, Codex, Gemini, and other AI implementers operate under the following rules.

### Before work

1. Read the relevant architecture and current-state documents.
2. Inspect the actual repository code relevant to the task.
3. Confirm the active phase/TD and its exact scope.
4. Identify protected/closed areas.
5. Confirm dependencies and existing contracts before changing them.

### During work

1. Implement the smallest necessary change.
2. Do not reopen closed work without explicit approval.
3. Do not reshape the repository merely to match a conceptual diagram.
4. Do not invent capabilities and report them as implemented.
5. Do not bypass authorization, verification, evidence, or provenance boundaries.
6. Do not widen scope because a broader change appears architecturally attractive.
7. Do not create duplicate backups or parallel project copies; Git is the recovery mechanism.

### After work

1. Run the relevant validation commands.
2. Report exact commands and results.
3. Report concerns and unresolved gaps explicitly.
4. Return a reviewable patch/diff.
5. Do not claim tests passed if they were not run.
6. Do not claim a capability exists unless the repository verifies it.

### When architecture and implementation disagree

Stop and surface the discrepancy.

Do not silently modify architecture, rewrite closed behavior, or invent a workaround outside the phase.

Architectural decisions belong to the project owner through the documented decision/phase process.

---

## 35. Strategy Non-Goals

This strategy intentionally does **not**:

- assign fixed implementation dates,
- assign every future capability to a numbered phase,
- prescribe one permanent programming language for every subsystem,
- require distributed infrastructure from day one,
- require a graph database because the asset model has relationships,
- require a specific browser technology before implementation evidence exists,
- require a specific proxy/traffic implementation language before benchmarks,
- treat AI as an authoritative security oracle,
- treat external tool output as automatically verified truth,
- define current repository behavior — that belongs to code and current-state documentation.

---

## 36. Source-of-Truth and Conflict Resolution

When sources disagree:

1. **Actual repository source code** — implemented behavior.
2. **`ARFA_MASTER_CONTEXT.md`** — current project state and execution roadmap.
3. **`ARCHITECTURE.md`** — architectural direction and boundaries.
4. **`PLATFORM_STRATEGY.md`** — long-term platform strategy.

This ordering applies to different questions.

For example:

- If the question is "does this feature exist?" → inspect code.
- If the question is "what phase is active?" → inspect Master Context.
- If the question is "where should the platform go architecturally?" → inspect Architecture.
- If the question is "how should new capabilities be admitted and scaled?" → inspect Strategy.

No strategic statement can override verified implementation facts.

---

## 37. Final Strategy Principle

ARFA should grow without becoming architecturally fragmented.

That means:

- **Broad destination** — no artificial ceiling on useful capability.
- **Controlled execution** — phases and TDs remain bounded.
- **One authorization model** — every execution path is constrained.
- **One truth discipline** — observation is not automatically a finding.
- **Evidence first** — security conclusions remain defensible.
- **Domain-native engines** — Web, API, Browser, Mobile, Web3, Traffic, Recon, and OAST can evolve according to their own semantics.
- **Composable extensions** — new capabilities have a controlled home without forcing rewrites.
- **Interoperability** — mature external tools can participate through explicit boundaries.
- **AI with boundaries** — intelligence can assist reasoning without becoming the authority for security truth.
- **Local-first evolution** — scale is introduced when requirements justify it.
- **Explicit decisions** — major architectural changes are recorded instead of being rediscovered inside implementation phases.

> **ARFA plans for the complete platform from the beginning, but earns each capability through explicit architecture, bounded implementation, verification, evidence, and review.**

---

**End of PLATFORM_STRATEGY.md**
