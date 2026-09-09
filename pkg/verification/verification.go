package verification

import (
	"arfa/pkg/models"
	"context"
	"strings"
)

// Status is the verification engine's classification for a candidate
// finding. A detector's Detect() call only ever produces a *candidate*;
// Status is what turns that candidate into something a report can present
// with an honest confidence label.
type Status string

const (
	Confirmed     Status = "CONFIRMED"
	Likely        Status = "LIKELY"
	Potential     Status = "POTENTIAL"
	FalsePositive Status = "FALSE_POSITIVE"
	Inconclusive  Status = "INCONCLUSIVE"
	Unverified    Status = "UNVERIFIED"
)

// Confidence is a deterministic, evidence-derived explanation of how much
// weight a Status should carry. It is additional information alongside
// Status, never a replacement for it: two Results can share a Status
// (e.g. both INCONCLUSIVE) while differing in Confidence because one had
// more of the verification sequence actually complete before it failed.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
	ConfidenceNone   Confidence = "NONE"
)

// maxProbeAttempts bounds every individual probe (repeat or control) to at
// most one retry. This is the entire retry budget for verification: a
// fixed, small constant, not a policy that can grow unbounded. Every
// attempt — original and retry — goes through the caller-supplied Prober,
// so it is subject to the same rate limiter, adaptive concurrency budget,
// timeout and cancellation as any other request the scanner makes.
const maxProbeAttempts = 2

// Prober performs one additional HTTP probe for verification purposes. The
// scanner supplies an adapter around its own httpclient/rate-limiter so
// verification requests share the same connection pool and adaptive pacing
// as the rest of the scan instead of opening a second, unmanaged path.
type Prober func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult

// Result carries the verification outcome plus the raw evidence used to
// reach it, so a report can show "original probe / verification probe /
// control probe" side by side rather than asking the reader to trust a
// label with no backing data.
type Result struct {
	Status       Status
	Detail       string
	RepeatProbe  *models.ProbeResult
	ControlProbe *models.ProbeResult

	// Confidence and ConfidenceReason are derived purely from Status and
	// which parts of the repeat/control sequence actually completed (see
	// evaluateConfidence). They are explainable (ConfidenceReason says
	// why) and reproducible (a pure function of the inputs) per
	// ARCHITECTURE.md §12, and never override Status.
	Confidence       Confidence
	ConfidenceReason string
}

// Normalize applies light, non-destructive cleanup to a raw probe result
// before it reaches a detector. It intentionally does not alter, truncate or
// reinterpret the evidence itself — only strips NUL bytes that break string
// matching on some targets.
func Normalize(p models.Payload, pr models.ProbeResult) models.ProbeResult {
	pr.Body = strings.ReplaceAll(pr.Body, "\x00", "")
	return pr
}

// Verify attempts controlled confirmation of a candidate finding using the
// minimum additional requests needed:
//
//  1. A repeat probe with the *same* payload value, to check the evidence
//     reproduces (rules out one-off network noise / transient errors).
//  2. A control probe with a benign, clearly non-attack value in the same
//     parameter, to check the evidence checker doesn't also fire on
//     ordinary input (rules out a static page, a WAF block page, or an
//     always-present string that coincidentally matches the detector's
//     marker).
//
// evidenceCheck is normally the originating detector's HasEvidence method,
// so verification re-runs the exact same test the detector used — it never
// invents a new, looser or stricter definition of "evidence" than the
// detector already committed to.
func Verify(ctx context.Context, ep models.Endpoint, param string, originalValue string, evidenceCheck func(models.ProbeResult) bool, probe Prober) Result {
	if probe == nil || evidenceCheck == nil {
		res := Result{Status: Inconclusive, Detail: "verification prober or evidence check unavailable"}
		res.Confidence, res.ConfidenceReason = evaluateConfidence(res.Status, false)
		return res
	}

	repeat := probeWithRetry(ctx, probe, ep, param, originalValue)
	res := Result{RepeatProbe: &repeat}

	if repeat.Err != nil {
		res.Status = Inconclusive
		res.Detail = "verification (repeat) probe failed after retry: " + repeat.Err.Error()
		res.Confidence, res.ConfidenceReason = evaluateConfidence(res.Status, false)
		return res
	}
	if !evidenceCheck(repeat) {
		res.Status = Potential
		res.Detail = "original evidence did not reproduce on an independent repeat probe"
		res.Confidence, res.ConfidenceReason = evaluateConfidence(res.Status, false)
		return res
	}

	control := probeWithRetry(ctx, probe, ep, param, "arfa-control-"+shortHash(originalValue))
	res.ControlProbe = &control
	if control.Err != nil {
		// Previously a failed control probe silently fell through to
		// CONFIRMED. That is not licensed: the false-positive check never
		// actually ran, so nothing rules out the benign value also
		// triggering the same evidence. Report INCONCLUSIVE instead - the
		// repeat probe did reproduce (see Confidence), but the
		// false-positive check itself could not complete.
		res.Status = Inconclusive
		res.Detail = "verification (control) probe failed after retry: evidence reproduced but the false-positive check could not complete: " + control.Err.Error()
		res.Confidence, res.ConfidenceReason = evaluateConfidence(res.Status, true)
		return res
	}
	if evidenceCheck(control) {
		res.Status = FalsePositive
		res.Detail = "evidence marker also present for a benign, non-attack control value"
		res.Confidence, res.ConfidenceReason = evaluateConfidence(res.Status, true)
		return res
	}

	res.Status = Confirmed
	res.Detail = "evidence reproduced on independent probe and absent for a benign control value"
	res.Confidence, res.ConfidenceReason = evaluateConfidence(res.Status, true)
	return res
}

// probeWithRetry issues probe up to maxProbeAttempts times, returning as
// soon as a probe succeeds (Err == nil) or ctx is canceled. This is the
// verification engine's only retry point, and it never grows the number of
// attempts beyond the fixed maxProbeAttempts constant.
func probeWithRetry(ctx context.Context, probe Prober, ep models.Endpoint, param, value string) models.ProbeResult {
	var last models.ProbeResult
	for attempt := 0; attempt < maxProbeAttempts; attempt++ {
		if ctx.Err() != nil {
			return models.ProbeResult{Err: ctx.Err()}
		}
		last = probe(ctx, ep, param, value)
		if last.Err == nil {
			return last
		}
	}
	return last
}

// evaluateConfidence derives an explainable, reproducible Confidence for a
// Status. repeatReproduced records whether the repeat probe actually
// reproduced the original evidence before the Status was decided, which is
// the one piece of information that distinguishes, for example, an
// INCONCLUSIVE caused by the repeat probe failing outright (no signal at
// all) from one caused by the control probe failing after the repeat probe
// already reproduced the evidence (partial signal). This mirrors
// ARCHITECTURE.md §12: Confidence is explainable, reproducible from
// available evidence, and never substitutes for Status.
func evaluateConfidence(status Status, repeatReproduced bool) (Confidence, string) {
	switch status {
	case Confirmed:
		return ConfidenceHigh, "evidence reproduced on an independent repeat probe and was absent for a benign control value"
	case FalsePositive:
		return ConfidenceHigh, "evidence also appeared for a benign, non-attack control value, so the original signal is not attack-specific"
	case Potential:
		return ConfidenceLow, "original evidence did not reproduce on an independent repeat probe"
	case Inconclusive:
		if repeatReproduced {
			return ConfidenceMedium, "evidence reproduced on repeat, but the false-positive check against a control value could not complete"
		}
		return ConfidenceNone, "verification could not gather any independent evidence before failing"
	default:
		return ConfidenceNone, "verification did not run"
	}
}

// shortHash keeps the control value visibly distinct from any real payload
// without pulling in extra formatting dependencies.
func shortHash(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	const hex = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = hex[(h>>(uint(i)*4))&0xF]
	}
	return string(b)
}
