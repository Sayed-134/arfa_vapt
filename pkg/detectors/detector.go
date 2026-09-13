package detectors

import (
	"arfa/pkg/models"
	"context"
	"strings"
)

type Probe func(context.Context, string, string, map[string]string, models.Payload) models.ProbeResult
type Detector interface {
	Name() string
	Category() string
	Detect(context.Context, models.Endpoint, models.Payload, Probe) []models.Finding
}

// EvidenceChecker is an optional additional interface a Detector can
// implement so the verification engine can re-run the exact same evidence
// test against a fresh probe result (a repeat request, or a control request
// with a benign value) without duplicating each detector's matching logic.
// Implementing this is additive: it does not change the Detector interface
// or break any existing detector that does not implement it.
type EvidenceChecker interface {
	HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool
}

// CaveatProvider is an optional additional interface a Detector can
// implement to attach a class-specific clarification of what its own
// CONFIRMED verification status does and does not establish. pkg/verification's
// CONFIRMED is defined generically (see verification.Verify's doc comment):
// evidence reproduced on an independent repeat probe and was absent for a
// benign control value. That generic definition does not change here and
// is shared by every detector. What differs by vulnerability class is what
// that reproducible evidence actually proves - server-side reflection
// evidence, for example, is not the same claim as proof of code execution.
// A detector implements CaveatProvider only when its own CONFIRMED status
// needs that distinction spelled out; the scanner attaches the returned
// text to a finding only when VerificationStatus is exactly CONFIRMED, and
// only for detectors that implement this interface - all other detectors
// and all other statuses are unaffected.
type CaveatProvider interface {
	ConfirmationCaveat() string
}
type Registry struct{ items []Detector }

func NewRegistry(ds ...Detector) *Registry {
	r := &Registry{}
	for _, d := range ds {
		r.items = append(r.items, d)
	}
	return r
}
func (r *Registry) All() []Detector { return r.items }
func params(ep models.Endpoint) []string {
	if len(ep.Parameters) > 0 {
		return ep.Parameters
	}
	return []string{"q", "id", "search", "page", "url", "file", "name"}
}
func inject(ep models.Endpoint, p string, v string) map[string]string { return map[string]string{p: v} }
func baseFinding(cat, name, sev, cvss, conf string, ep models.Endpoint, param string, p models.Payload, pr models.ProbeResult, evidence string) models.Finding {
	return models.Finding{Category: cat, Name: name, Severity: sev, CVSS: cvss, Confidence: conf, Endpoint: ep.URL, Parameter: param, Payload: p.Value, Encoding: "plain", Evidence: evidence, PoC: pr.URL, Status: pr.Status, Impact: "Requires application-specific validation.", Remediation: "Validate and constrain untrusted input; use context-appropriate safe APIs."}
}
func containsFold(body string, ss ...string) bool {
	b := strings.ToLower(body)
	for _, s := range ss {
		if strings.Contains(b, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func containsOutsidePayload(body, payload string, markers ...string) bool {
	cleaned := strings.ReplaceAll(body, payload, "")
	return containsFold(cleaned, markers...)
}
