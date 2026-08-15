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
		return Result{Status: Inconclusive, Detail: "verification prober or evidence check unavailable"}
	}

	repeat := probe(ctx, ep, param, originalValue)
	res := Result{RepeatProbe: &repeat}

	if repeat.Err != nil {
		res.Status = Inconclusive
		res.Detail = "verification (repeat) probe failed: " + repeat.Err.Error()
		return res
	}
	if !evidenceCheck(repeat) {
		res.Status = Potential
		res.Detail = "original evidence did not reproduce on an independent repeat probe"
		return res
	}

	control := probe(ctx, ep, param, "arfa-control-"+shortHash(originalValue))
	res.ControlProbe = &control
	if control.Err == nil && evidenceCheck(control) {
		res.Status = FalsePositive
		res.Detail = "evidence marker also present for a benign, non-attack control value"
		return res
	}

	res.Status = Confirmed
	res.Detail = "evidence reproduced on independent probe and absent for a benign control value"
	return res
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
