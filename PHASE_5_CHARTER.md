# ARFA VAPT — Phase 5 Charter

**Status:** Active Phase Definition — Phase 5
**Phase 4 Status:** CLOSED / FROZEN
**Created:** 2026-09-30
**Supersedes:** All prior Phase 5 charter drafts

---

## 1. Phase Definition

**Phase:** Phase 5
**Title:** Application Visibility Gap
**Status:** Proposed / Ready for WI-1
**Scope:** Authorized VAPT platform covering Web2, Web3, and Mobile
**Phase Type:** Capability-gap investigation followed by evidence-driven implementation

Phase 5 exists to address a field-proven limitation in ARFA's ability to discover and assess meaningful application surfaces when those surfaces are materialized through client-side application behavior rather than being directly present in the initial HTTP document.

This phase does **not** begin with a predetermined browser, proxy, rendering engine, or implementation technology.

The phase begins with the demonstrated capability gap and determines the minimum capability required to close it.

---

## 2. Problem Statement

Field testing demonstrated that ARFA can successfully reach an application server and receive a valid application response, while still failing to discover the meaningful application surface exposed to a user.

The tested target was:

`https://kyc-bounty.amlbot.com`

The observed behavior was:

1. ARFA successfully reached the target.
2. The target returned HTTP 200 application content.
3. The returned document was an SPA shell containing an empty application root and JavaScript bundle references.
4. ARFA's current discovery path did not execute the client-side JavaScript required to materialize the application's dynamic surface.
5. ARFA discovered only one endpoint and zero real application parameters.
6. Fallback parameters were introduced:

   * `id`
   * `page`
   * `q`
   * `search`
   * `url`
7. The scanner subsequently executed substantial probe coverage against those fallback parameters.
8. Baseline produced zero findings.
9. Standard mode produced five XSS findings, all marked `FALSE_POSITIVE` by the existing verification logic.
10. Independent inspection of the referenced JavaScript bundle identified real application routes:

    * `/form-a`
    * `/form-b`
    * `/generate`

The evidence provides **strong evidence** of an Application Visibility Gap:

> ARFA can reach the application and obtain its initial SPA document, but its current discovery path does not currently materialize the application-defined surface exposed through client-side execution.

This establishes the capability gap, but does not yet establish that JavaScript execution alone is sufficient, nor does it establish a single final root cause. Determining the exact capability boundary is the purpose of WI-1.

---

## 3. Field Evidence Package

### 3.1 Baseline Scan

Target:

`https://kyc-bounty.amlbot.com`

Mode:

`quick`

Observed:

* Reachability: `reachable`
* HTTP: `200 OK`
* Requests: `1,225`
* Endpoints: `1`
* Parameters: `0`
* Fallback parameters: `id`, `page`, `q`, `search`, `url`
* Findings: `0`
* Coverage: `45` cells
* Duration: `107,299 ms`
* Errors: `0`
* Next actions: `[]`

### 3.2 Standard Scan

Mode:

`standard`

Observed:

* Reachability: `reachable`
* HTTP: `200 OK`
* Requests: `7,250`
* Endpoints: `1`
* Findings: `5`
* All five findings: `FALSE_POSITIVE`
* Parameters represented in findings:

  * `id`
  * `search`
  * `page`
  * `url`
  * `q`
* Duration: `346,059 ms`
* Errors: `0`

The existing verification behavior correctly classified the observed XSS signals as false positives because the evidence marker was also present for a benign control value.

### 3.3 SPA Shell Evidence

The application response contained, among other elements:

```html
<div id="root"></div>
<script type="module" crossorigin src="/assets/index-B0RLbqBG.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-Dl4GaYab.css">
```

This demonstrates that the initial document is an application shell whose meaningful UI is expected to be materialized by client-side code.

### 3.4 JavaScript Bundle Evidence

The referenced JavaScript bundle was independently inspected:

```text
/assets/index-B0RLbqBG.js
```

Observed technology and application information included:

* React `18.3.1`
* Ant Design `5.29.1`
* React Router `v6`
* Axios `1.13.2`
* Application-defined routes found within the bundle:

  * `/form-a`
  * `/form-b`
  * `/generate`

The routes were found as **definitions inside the JavaScript bundle**. They were not visited or discovered by ARFA during the scan. This distinction is essential: the bundle inspection establishes that a client-side application surface exists, but does not establish that ARFA can currently materialize or reach it.

### 3.5 Report Evidence

The generated `scan_report.html` files confirm the externally visible scan results:

* Baseline report: reachable, 1 endpoint, 1,225 requests, 0 findings, 0 errors.
* Standard report: reachable, 1 endpoint, 7,250 requests, 5 XSS findings, all `FALSE_POSITIVE`, 0 errors.

### 3.6 Evidence Limitations

The original `/tmp/amlbot-home.html` file is no longer available because it was stored under `/tmp` and was removed after reboot.

Its absence does not invalidate the evidence package because the relevant HTML response was preserved inside scan evidence and the generated reports remain available.

### 3.7 Evidence Summary Table

| Type | Evidence |
| --- | --- |
| ARFA observed response | SPA HTML shell + `<div id="root"></div>` + JS bundle reference |
| Bundle inspection | React / Ant Design / React Router / Axios |
| Application-defined surface | `/form-a`, `/form-b`, `/generate` (definitions inside the bundle) |
| ARFA discovered surface | 1 endpoint |
| Fallback behavior | `id`, `page`, `q`, `search`, `url` |
| Assessment result | Baseline: 0 findings; Standard: 5 XSS, all `FALSE_POSITIVE` |
| Interpretation | A gap exists between the application surface defined in the client bundle and the surface ARFA currently materializes |

---

## 4. Observed Facts vs Interpretation vs Hypothesis

Phase 5 must preserve this distinction.

### 4.1 Observed Facts

* The target was reachable.
* ARFA received application HTML.
* The HTML contained an SPA root and JavaScript bundle references.
* ARFA discovered one endpoint.
* ARFA discovered zero real parameters.
* Fallback parameters were used.
* The JavaScript bundle contained additional application routes as definitions.
* Standard-mode XSS signals were classified as `FALSE_POSITIVE`.

### 4.2 Evidence-Supported Interpretation

The current discovery path does not materialize the client-side application surface represented by the JavaScript application.

### 4.3 Leading Capability Hypothesis

JavaScript execution / browser-assisted rendering may be required to expose the missing application surface.

### 4.4 Additional Hypotheses

WI-1 must determine whether the required capability also includes:

* Browser state
* DOM/rendered-state observation
* XHR/fetch/network observation
* Dynamic API discovery
* Session or application state
* Other runtime behavior

No implementation technology is selected by this Charter.

### 4.5 Governing Distinction

```text
Transport reachable
        ≠
Application assessable
        ≠
Meaningful coverage
        ≠
No vulnerabilities
```

The observed field condition is:

```text
ARFA reached the application (real HTML, real title, HTTP 200)
        ↓
ARFA received SPA shell (empty root div)
        ↓
Current discovery path does not execute client-side JavaScript
        ↓
The client-side application surface was not materialized by ARFA
        ↓
ARFA used fallback parameters
        ↓
ARFA produced no meaningful findings from the discovered application surface,
because the meaningful application surface had not been materialized
        ↓
Result: transport reachability and probe activity did not establish meaningful application coverage
```

This is the gap Phase 5 must address.

---

## 5. Phase Goal

The goal of Phase 5 is to determine and implement the **minimum reusable capability required for ARFA to discover meaningful client-side application surfaces that its current static discovery path cannot expose**, while preserving the existing scanner, verification, evidence, authorization, and reporting contracts.

Phase completion requires field evidence showing that the identified visibility gap has been materially reduced or closed for the demonstrated class of application.

---

## 6. Methodology

Phase 5 follows this sequence:

```text
Field Evidence
    ↓
Capability Gap
    ↓
Exact Capability Boundary Investigation
    ↓
Mature Market / Implementation Research
    ↓
Reuse
    ↓
Integrate
    ↓
Adapt
    ↓
Build only if necessary
    ↓
Minimum Implementation
    ↓
Engineering Validation
    ↓
Field Validation
    ↓
Phase Close
```

The phase must not select implementation technology before the capability requirement is sufficiently established.

A new capability is not admitted merely because it is useful, familiar, or part of the long-term platform vision.

---

## 7. Project Owner

**Project Owner = the user who commissioned this Phase 5 Charter.**

The Project Owner determines:

* whether the field evidence is sufficient;
* whether the capability gap is real;
* whether WI-1 has identified the capability boundary;
* which mature implementation/workflow should be evaluated;
* whether reuse, integration, adaptation, or new implementation is justified;
* whether the proposed implementation remains within Phase 5 scope;
* whether field validation demonstrates meaningful progress;
* whether Phase 5 is ready to close.

Claude/Gemini/Codex are implementation agents only.

They do not independently redefine the Phase, select unrelated architecture, reopen closed milestones, or expand scope.

---

## 8. WI-1 — Exact Capability Boundary Investigation

### 8.1 Objective

Determine exactly what ARFA is currently missing in order to materialize and discover the application's meaningful client-side surface.

### 8.2 Required Questions

WI-1 must determine:

1. Is JavaScript execution alone sufficient?
2. Is DOM/rendered-state inspection required?
3. Is browser state required?
4. Is XHR/fetch/network observation required?
5. Is dynamic API discovery required?
6. Are session/cookie/storage mechanisms required?
7. Are multiple capabilities required together?
8. At what point does the missing capability begin and end relative to ARFA's current crawler/discovery architecture?

### 8.3 Investigation Principle

WI-1 must investigate the capability boundary rather than implement a solution.

The investigation may use controlled experiments, existing tools, browser/runtime inspection, captured traffic, or other evidence necessary to isolate the dependency.

The investigation must not turn into an implementation project.

### 8.4 Required Output

WI-1 must produce:

* confirmed capability gap;
* capability boundary;
* observed prerequisites;
* evidence for each required capability;
* capabilities tested and shown unnecessary;
* unresolved uncertainty, if any;
* minimum capability requirement for WI-2.

### 8.5 Capability Requirement

The capability requirement describes **WHAT ARFA needs to do, not HOW it should be implemented**.

It must be:

* evidence-supported;
* actionable for WI-2;
* tied to observable success criteria;
* independent of technology choice.

### 8.6 WI-1 Completion

WI-1 is complete when available evidence provides a sufficiently supported interpretation to allow WI-2 to research concrete implementation options.

Absolute proof of one single root cause is **not required**.

"Sufficiently supported" means:

* the evidence identifies the location/nature of the divergence sufficiently;
* important alternatives are ruled out or explicitly documented as unresolved;
* the capability requirement is specific enough for WI-2;
* no unsupported certainty is presented as fact.

The **Project Owner** decides whether WI-1 is complete.

### 8.7 WI-1 Completion Criterion

WI-1 is complete only when there is sufficient evidence to state:

> "ARFA needs capability X, and optionally capabilities Y/Z, to materialize this class of application surface."

The statement must be evidence-backed rather than technology-backed.

---

## 9. WI-2 — Mature Implementation Research

### 9.1 Input

The capability requirement produced by WI-1.

### 9.2 Objective

Identify the strongest mature implementation/workflow for the exact capability established by WI-1.

### 9.3 Research Scope

Potential reference implementations may include, where relevant:

* Burp Suite
* OWASP ZAP
* mitmproxy
* Playwright
* Puppeteer
* browser/runtime implementations
* specialized application-discovery tooling
* other mature implementations directly relevant to the confirmed capability

The list is illustrative, not prescriptive.

### 9.4 Evaluation Criteria

Candidate implementations must be evaluated against:

* required capability coverage;
* maturity;
* stability;
* integration feasibility;
* observability;
* request/response interoperability;
* session/state handling;
* licensing and operational constraints;
* ability to preserve ARFA's deterministic scanning model;
* evidence/provenance compatibility;
* maintenance burden;
* architectural fit.

### 9.5 Priority Order

The decision order is:

1. **Reuse**
2. **Integrate**
3. **Adapt**
4. **Build**

Building an equivalent subsystem from scratch requires evidence that the preceding options are unsuitable.

### 9.6 Required Output

WI-2 must produce:

* evaluated mature implementations/workflows;
* capability-to-implementation mapping;
* reuse/integration/adaptation opportunities;
* limitations;
* recommendation for the minimum viable implementation approach.

WI-2 must not implement the selected solution.

Technology selection occurs in WI-2, not WI-1.

### 9.7 WI-2 Completion

WI-2 is complete when the technical direction is sufficiently defined for a minimum-scope implementation.

The **Project Owner** approves the transition from WI-2 to WI-3.

---

## 10. WI-3 — Minimum Implementation

### 10.1 Input

The technical direction selected by WI-2.

### 10.2 Objective

Implement only the capability justified by WI-1 and WI-2.

### 10.3 Rules

The implementation must:

* remain additive;
* preserve existing contracts;
* preserve authorization boundaries;
* preserve evidence provenance;
* preserve verification behavior;
* preserve existing Phase 1–4 behavior;
* avoid unrelated refactoring;
* avoid rebuilding mature external capabilities unnecessarily;
* expose only the minimum new surface required to address the Phase 5 gap.

No browser, proxy, rendering engine, traffic subsystem, or other technology may be added merely because it is commonly used for this class of problem.

Each new component must be justified by the confirmed capability requirement.

### 10.4 Output

WI-3 produces the minimum implementation required to address the demonstrated capability gap, together with the resulting honest assessment behavior.

### 10.5 WI-3 Completion

WI-3 is complete when field validation demonstrates that the identified application-visibility gap is materially addressed for the validated gap class and no regression is introduced.

"Materially addressed" means:

* the observed gap class from WI-1 no longer occurs under the validated conditions;
* field validation on the same target class demonstrates the improvement;
* honest assessment behavior is demonstrated, with no false "0 findings" caused by inability to meaningfully assess the application.

The goal is to prove the capability, not to create a one-off workaround for a single target.

---

## 11. Honest Assessment Requirement

Phase 5 must not allow inability to assess the application layer to be implicitly represented as a successful negative assessment.

The system must distinguish:

* **Transport Reachability**
* **Application Visibility**
* **Surface Discovery**
* **Assessment Execution**
* **Verification**
* **Evidence Quality**
* **Meaningful Coverage**

The following must never be treated as equivalent:

> `reachable` ≠ `application assessable` ≠ `meaningful coverage` ≠ `no vulnerabilities`

If the application surface cannot be materialized, the resulting limitation must be represented honestly rather than hidden behind successful HTTP reachability or large request counts.

Fallback probing must not be presented as equivalent to discovering and assessing the application's real parameters.

The exact representation is intentionally **not** defined before WI-1.

* WI-1 documents the current failure or ambiguity.
* WI-2 evaluates candidate approaches for preserving assessment truth.
* WI-3 implements the appropriate mechanism as part of the selected solution.

The mechanism may be a readiness model, coverage model, reporting state, execution state, or another boundary determined by the investigation.

Do **not** predefine formal states such as "tested / not tested / could not test" before the investigation establishes the correct representation.

---

## 12. Scope

### 12.1 In Scope

* Exact investigation of the Application Visibility Gap.
* Client-side application discovery.
* JavaScript execution capability.
* Browser-assisted rendering where evidence establishes the need.
* Runtime application-state discovery where required.
* Dynamic route discovery.
* Dynamic form/control discovery.
* Dynamic API/network discovery where required.
* Integration with the existing discovery/scanning pipeline where justified.
* Evidence and provenance for newly discovered application surface.
* Field validation of the implemented capability.

### 12.2 Out of Scope

Unless explicitly justified by WI-1 and approved as part of Phase 5:

* Full browser automation platform.
* Full proxy/interception platform.
* Rebuilding Burp Suite, ZAP, or equivalent tools.
* Generic browser testing unrelated to the visibility gap.
* Full traffic history/repeater/intruder subsystems.
* Mobile assessment implementation.
* Web3 assessment implementation.
* New vulnerability classes unrelated to the visibility gap.
* AI-driven autonomous decision making.
* Dashboard redesign.
* Large-scale architecture refactoring.
* Reopening Phase 1–4 work.

---

## 13. Scope Control

Any proposed change must answer:

1. What evidence requires it?
2. Which Phase 5 capability does it provide?
3. Why can the capability not be obtained through reuse/integration/adaptation?
4. What existing contract does it touch?
5. What is the smallest implementation surface?
6. How will it be field validated?

If these questions cannot be answered, the change is outside Phase 5.

---

## 14. Multi-Cause Scenario

The Application Visibility Gap may have multiple contributing causes.

For example, investigation may establish that:

```text
JavaScript execution
        +
browser state
        +
network observation
```

is required.

In that case, Phase 5 must not artificially reduce the problem to JavaScript execution alone.

Conversely, if experiments demonstrate that JavaScript execution alone is sufficient for the demonstrated capability, additional browser/network subsystems must not be introduced without independent justification.

The phase follows evidence rather than a predetermined architecture.

Each capability must satisfy:

```text
Original Gap
    ↓
Necessary?
    ↓
WI-2 Research
    ↓
Minimum Capability
```

Discovering several possible technical improvements is not, by itself, permission to implement all of them.

---

## 15. Technology Non-Selection

This Charter intentionally does **not** select:

* Playwright
* Puppeteer
* Chromium
* Firefox
* WebDriver
* mitmproxy
* Burp Suite
* ZAP
* any specific rendering engine
* any specific proxy architecture

Based on current field evidence, the leading hypothesis is:

* **JavaScript execution / browser-assisted rendering**

Other hypotheses remain open until WI-1 completes:

* Browser
* Proxy / Traffic interception
* Session import
* uTLS / TLS modification
* WAF/challenge detection
* protocol-specific transport changes
* any specific third-party implementation

No technology is selected by this Charter.

Technology selection is deferred to WI-2.

---

## 16. Existing Architecture Protection

Phase 5 must preserve the closed foundation established by Phases 1–4.

Closed Phase 1–4 contracts and behavior must not be reopened or modified unless a direct Phase 5 requirement is demonstrated and explicitly approved.

Protected existing components include, unless WI-1 establishes a direct requirement:

* `pkg/crawler`
* `pkg/detectors`
* `pkg/scanner`
* `pkg/payloads`
* `pkg/httpclient`
* `pkg/ratelimiter`
* `cmd/arfa`
* `cmd/test-target`
* `go.mod`
* `go.sum`

`pkg/report` remains a minimal integration boundary unless Phase 5 evidence directly requires more.

---

## 17. Completion Criteria

Phase 5 may close only when all of the following are satisfied:

### 17.1 Capability

The exact Application Visibility Gap has been identified and the required capability has been demonstrated.

### 17.2 Research

A mature implementation/workflow has been evaluated and the choice between reuse, integration, adaptation, or new implementation is evidence-backed.

### 17.3 Implementation

The minimum justified capability has been implemented without unnecessary architectural expansion.

### 17.4 Engineering Validation

Relevant build, test, race, formatting, and static-analysis checks pass according to the project's standard validation workflow.

### 17.5 Field Validation

A controlled authorized field test demonstrates that the new capability can discover or materialize application surface that the previous implementation could not.

### 17.6 Assessment Integrity

The newly discovered surface is distinguishable from fallback/generated probing and remains traceable through ARFA's evidence model.

### 17.7 Honest Reporting

ARFA does not represent transport reachability or fallback activity as equivalent to meaningful application coverage.

### 17.8 Scope

No unrelated work remains embedded in the Phase.

For a multi-cause gap, each implemented capability must independently remain necessary for the original Application Visibility Gap.

---

## 18. Phase Boundary

Phase 4 remains **CLOSED / FROZEN**.

Phase 5 must not modify, reinterpret, or reopen Phase 4 contracts.

Any capability outside the demonstrated Application Visibility Gap requires a separate capability-intake decision.

Phase 5 ends when the demonstrated Application Visibility Gap is sufficiently addressed by the minimum justified capability.

Phase 5 does **not** automatically open future work concerning:

* full browser automation;
* complete traffic interception;
* proxy history;
* repeater;
* intruder-style workflows;
* mobile;
* Web3;
* continuous recon;
* dashboard expansion;
* autonomous agents.

Those capabilities may be considered independently through future evidence-driven phases.

---

## 19. Documentation

This Charter is maintained as a standalone document:

```text
PHASE_5_CHARTER.md
```

It is referenced from:

```text
ARFA_MASTER_CONTEXT.md
```

Phase 4 documentation remains unchanged and closed.

### 19.1 Documentation Consistency

The three primary documents must not contradict each other:

* `ARCHITECTURE.md` — architectural direction and boundaries.
* `PLATFORM_STRATEGY.md` — long-term strategy and capability intake.
* `ARFA_MASTER_CONTEXT.md` — current project state, closed milestones, current phase.

This Charter (`PHASE_5_CHARTER.md`) is subordinate to those three documents and defines only Phase 5 execution.

### 19.2 Source-of-Truth Reference

Different documents answer different questions. They are not a governing hierarchy over one another:

```text
SOURCE OF TRUTH FOR IMPLEMENTED BEHAVIOR
    Repository / main source code

CURRENT PROJECT STATE
    ARFA_MASTER_CONTEXT.md

ARCHITECTURAL REFERENCE
    ARCHITECTURE.md

STRATEGIC REFERENCE
    PLATFORM_STRATEGY.md

CURRENT PHASE BOUNDARY
    PHASE_5_CHARTER.md

HISTORICAL PHASE REFERENCE
    PHASE_4_TD_SPECS.md
```

If any document conflicts with the implemented repository behavior, the repository source code remains authoritative for what is actually implemented.

---

## 20. WI-1 Start Gate

WI-1 starts only after both conditions are satisfied:

1. `PHASE_5_CHARTER.md` has been merged into the repository.
2. The Project Owner has reviewed and approved this Charter.

Additionally, WI-1 may begin only when:

* The field evidence package is accepted as sufficient.
* No technology has been preselected as the solution.
* The investigation scope is limited to the Application Visibility Gap.
* Existing Phase 1–4 contracts remain protected.
* The target capability is clearly defined as application visibility/materialization rather than a generic browser or proxy project.

Until both conditions are satisfied, Phase 5 is defined but WI-1 is not started.

The first implementation decision of Phase 5 must therefore be **an investigation, not a code change**.

---

## 21. Phase 5 Operating Principle

> **Do not build what the evidence has not yet shown ARFA needs.**

Phase 5 moves ARFA from:

> reaching an application

toward:

> understanding and materializing the application's actual assessable surface.

The implementation must follow the capability requirement, and the capability requirement must follow field evidence.

---

**End of PHASE_5_CHARTER.md**
