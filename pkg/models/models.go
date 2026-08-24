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
}

type ScanStats struct {
	Pages          int   `json:"pages"`
	AdaptiveBudget int   `json:"adaptive_budget,omitempty"`
	Endpoints      int   `json:"endpoints"`
	Parameters     int   `json:"parameters"`
	Requests       int64 `json:"requests"`
	Errors         int64 `json:"errors"`
	DurationMS     int64 `json:"duration_ms"`
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
}

// ScanResult remains an alias for source compatibility with the v2 baseline.
type ScanResult = ScanEnvelope
