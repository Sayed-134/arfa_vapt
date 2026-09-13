package models

import "net/http"

type Endpoint struct {
	URL            string   `json:"url"`
	Method         string   `json:"method"`
	Parameters     []string `json:"parameters"`
	FormParameters []string `json:"form_parameters,omitempty"`
}

type Payload struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Value    string `json:"value"`
	Source   string `json:"source"`
}

type ProbeResult struct {
	URL        string
	Method     string
	Status     int
	Headers    http.Header
	Body       string
	DurationMS int64
	Err        error
}

type Finding struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	CVSS        string `json:"cvss"`
	Confidence  string `json:"confidence"`
	Endpoint    string `json:"endpoint"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	Encoding    string `json:"encoding"`
	Evidence    string `json:"evidence"`
	PoC         string `json:"poc"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	Status      int    `json:"status"`

	// VerificationStatus is one of CONFIRMED, LIKELY, POTENTIAL, FALSE_POSITIVE
	// or INCONCLUSIVE. It is set by the verification engine after the
	// detector's initial candidate finding; UNVERIFIED means the
	// verification engine did not run for this finding (e.g. IDOR
	// heuristic findings, which need application-specific confirmation
	// the engine cannot perform on its own yet).
	VerificationStatus string `json:"verification_status"`
	VerificationDetail string `json:"verification_detail,omitempty"`

	// VerificationConfidence and VerificationConfidenceReason are additive
	// (see ARCHITECTURE.md §12: Confidence Evaluation). They are derived
	// from the verification engine's own evidence sequence, are additional
	// to VerificationStatus, and never replace it: two findings can share
	// a VerificationStatus while differing in VerificationConfidence.
	// Empty for any finding produced by code that did not run verification
	// (e.g. IDOR heuristic findings) or by an older build, so existing
	// consumers see no change unless this data actually exists.
	VerificationConfidence       string `json:"verification_confidence,omitempty"`
	VerificationConfidenceReason string `json:"verification_confidence_reason,omitempty"`

	// VerificationCaveat is an additive, class-specific clarification of
	// what a CONFIRMED VerificationStatus does and does not establish for
	// this particular finding (see detectors.CaveatProvider and Technical
	// Debt item #10 - XSS CONFIRMED meaning reproducible reflection, not
	// proof of JavaScript execution). It never changes VerificationStatus,
	// VerificationDetail or VerificationConfidence, and is only populated
	// when the originating detector implements CaveatProvider and this
	// finding's VerificationStatus is exactly CONFIRMED; empty (and
	// omitted from JSON) otherwise, so existing consumers see no change.
	VerificationCaveat string `json:"verification_caveat,omitempty"`

	// EvidenceDetail is the structured evidence record for this finding,
	// added in Milestone 2. It is additive and optional: nil for any
	// finding produced by code that does not populate it, and omitted from
	// JSON entirely in that case so existing consumers see no change.
	EvidenceDetail *Evidence `json:"evidence_detail,omitempty"`
}

// Evidence is a structured, redaction-bounded record of what was actually
// observed for a finding: the original probe plus, when the verification
// engine ran, a human-readable trace of the repeat/control probes it made.
// It deliberately does NOT carry raw request/response headers or full
// response bodies — only what's needed to audit a finding without risking
// credential/secret leakage into JSON reports or (later) LLM prompts.
type Evidence struct {
	Timestamp string `json:"timestamp"`
	Endpoint  string `json:"endpoint"`
	Parameter string `json:"parameter"`
	Category  string `json:"category"`

	RequestMethod string `json:"request_method"`
	RequestURL    string `json:"request_url"`

	ResponseStatus int `json:"response_status"`
	// ResponseSnippet is truncated to a bounded length (see
	// pkg/scanner.evidenceSnippetLimit) — never the full response body.
	ResponseSnippet string `json:"response_snippet"`
	// ResponseHash is sha256 of the *full* response body, so two findings
	// can be compared/correlated for identical evidence without storing
	// the full body twice.
	ResponseHash string `json:"response_hash"`

	// VerificationTrace is a short, human-readable log of what the
	// verification engine did to reach its status ("repeat probe:
	// evidence reproduced", "control probe: evidence absent"). It is prose,
	// not raw probe data, by design — see the redaction note above.
	VerificationTrace []string `json:"verification_trace,omitempty"`
}

// CoverageState is the coarse, planner-facing summary of how much testing an
// endpoint × parameter × vulnerability-class combination has received. It is
// intentionally coarser than Finding.VerificationStatus (which keeps full
// fidelity, e.g. distinguishing LIKELY from POTENTIAL) - Coverage exists to
// answer "was this tried, and did it resolve", not to duplicate the
// verification engine's own vocabulary.
type CoverageState string

const (
	CoverageNotAttempted CoverageState = "not_attempted"
	CoverageAttempted    CoverageState = "attempted"
	CoverageVerified     CoverageState = "verified"
	CoverageFailed       CoverageState = "failed"       // resolved as a false positive
	CoverageInconclusive CoverageState = "inconclusive" // tried, ambiguous result
)

// CoverageEntry is one endpoint × parameter × vulnerability-class cell in
// the coverage matrix.
type CoverageEntry struct {
	Endpoint  string        `json:"endpoint"`
	Parameter string        `json:"parameter"`
	Category  string        `json:"category"`
	State     CoverageState `json:"state"`
}

// NextAction is one deterministically-derived recommendation from the
// Milestone 2 planner: what to test next and why. It is advisory data only
// - nothing in this codebase executes a NextAction automatically. See
// pkg/planner.
type NextAction struct {
	Endpoint  string `json:"endpoint"`
	Parameter string `json:"parameter"`
	Category  string `json:"category"`
	Reason    string `json:"reason"`
	// Priority is lower-is-more-important and is derived purely from
	// CoverageState (see pkg/planner) - it is not a machine-learned or
	// heuristic risk score.
	Priority int `json:"priority"`
}

type ScanStats struct {
	Pages          int   `json:"pages"`
	AdaptiveBudget int   `json:"adaptive_budget,omitempty"`
	Endpoints      int   `json:"endpoints"`
	Parameters     int   `json:"parameters"`
	Requests       int64 `json:"requests"`
	Errors         int64 `json:"errors"`
	DurationMS     int64 `json:"duration_ms"`

	// JobsPlanned is the total number of probe jobs the scheduler generated
	// for this scan. Milestone 2 streams jobs instead of materializing them
	// all in memory at once (see pkg/scanner), so this is a count observed
	// during streaming, not the length of a pre-built slice.
	JobsPlanned int64 `json:"jobs_planned,omitempty"`
	// JobsCapped is true if the scheduler stopped generating new jobs
	// because Config.MaxJobs was reached before all endpoint/detector/
	// payload/parameter/encoding combinations were scheduled.
	JobsCapped bool `json:"jobs_capped,omitempty"`

	// TimeBudgetExhausted is true if Config.MaxDuration was set and the
	// scan's internal time budget elapsed before the scan would otherwise
	// have finished (see pkg/scanner.Scan). It is additive and omitted
	// from JSON when false, so existing consumers see no change unless a
	// scan actually ran out of time. Distinct from a caller-canceled ctx:
	// this is only ever set when the scan's own deadline - not an
	// external cancellation - is what stopped it.
	TimeBudgetExhausted bool `json:"time_budget_exhausted,omitempty"`
}

// ScanScope is an auditable record of the explicit authorization decision.
// It contains no inferred claim about target ownership or legal permission.
type ScanScope struct {
	Authorized          bool   `json:"authorized"`
	AuthorizationMethod string `json:"authorization_method"`
	AuthorizedAt        string `json:"authorized_at"`
}

type ReachabilityCheck struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	DurationMS int64  `json:"duration_ms"`
}

type Reachability struct {
	Status      string              `json:"status"`
	Reason      string              `json:"reason"`
	ResolvedIPs []string            `json:"resolved_ips,omitempty"`
	SelectedURL string              `json:"selected_url,omitempty"`
	Checks      []ReachabilityCheck `json:"checks,omitempty"`
}

// ScanEnvelope is the versioned, cross-language result contract. Fields from
// the v2 baseline remain additive and stable for existing consumers.
type ScanEnvelope struct {
	SchemaVersion string       `json:"schema_version"`
	Target        string       `json:"target"`
	Scope         ScanScope    `json:"scope"`
	StartedAt     string       `json:"started_at"`
	Mode          string       `json:"mode"`
	Reachability  Reachability `json:"reachability"`
	Stats         ScanStats    `json:"stats"`
	Findings      []Finding    `json:"findings"`

	// Coverage and NextActions are Milestone 2 additions. Both are omitted
	// from JSON when empty (e.g. -preflight-only runs, or a scan that never
	// reached job scheduling) so the envelope shape for existing consumers
	// is unchanged unless this data actually exists.
	Coverage    []CoverageEntry `json:"coverage,omitempty"`
	NextActions []NextAction    `json:"next_actions,omitempty"`
}

// ScanResult remains an alias for source compatibility with the v2 baseline.
type ScanResult = ScanEnvelope
