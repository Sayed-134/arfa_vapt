package verification

import (
	"arfa/pkg/models"
	"context"
	"errors"
	"testing"
)

func TestVerifyConfirmed(t *testing.T) {
	calls := 0
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		calls++
		body := "safe"
		if value == "attack" {
			body = "evidence-marker"
		}
		return models.ProbeResult{Body: body}
	}
	check := func(pr models.ProbeResult) bool { return pr.Body == "evidence-marker" }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != Confirmed {
		t.Fatalf("expected Confirmed, got %s (%s)", res.Status, res.Detail)
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 verification probes (repeat + control) when both succeed first try, got %d", calls)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("expected HIGH confidence for Confirmed, got %s (%s)", res.Confidence, res.ConfidenceReason)
	}
	if res.ConfidenceReason == "" {
		t.Fatal("expected a non-empty confidence reason")
	}
}

func TestVerifyFalsePositive(t *testing.T) {
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Body: "evidence-marker"} // fires even for the benign control value
	}
	check := func(pr models.ProbeResult) bool { return pr.Body == "evidence-marker" }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != FalsePositive {
		t.Fatalf("expected FalsePositive, got %s (%s)", res.Status, res.Detail)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("expected HIGH confidence for FalsePositive (it's a clear result, just the opposite conclusion), got %s", res.Confidence)
	}
}

func TestVerifyPotential(t *testing.T) {
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Body: "nothing here"}
	}
	check := func(pr models.ProbeResult) bool { return pr.Body == "evidence-marker" }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != Potential {
		t.Fatalf("expected Potential, got %s (%s)", res.Status, res.Detail)
	}
	if res.Confidence != ConfidenceLow {
		t.Fatalf("expected LOW confidence for Potential, got %s", res.Confidence)
	}
}

func TestVerifyInconclusiveOnProbeError(t *testing.T) {
	calls := 0
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		calls++
		return models.ProbeResult{Err: errors.New("boom")}
	}
	check := func(pr models.ProbeResult) bool { return true }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != Inconclusive {
		t.Fatalf("expected Inconclusive, got %s (%s)", res.Status, res.Detail)
	}
	// Bounded retry: a persistently failing prober must be tried up to
	// maxProbeAttempts times for the repeat probe and no more - it must
	// never loop unboundedly, and it must not skip the retry either.
	if calls != maxProbeAttempts {
		t.Fatalf("expected exactly maxProbeAttempts=%d calls for a persistently failing repeat probe, got %d", maxProbeAttempts, calls)
	}
	if res.Confidence != ConfidenceNone {
		t.Fatalf("expected NONE confidence when no evidence could be gathered at all, got %s", res.Confidence)
	}
}

// TestVerifyRetrySucceedsOnSecondAttempt is the direct regression test for
// the Bounded Retry Logic gap: a probe that fails once due to a transient
// error and then succeeds must not be treated as a hard failure - it
// should be retried (once, per maxProbeAttempts) and, on success, proceed
// through the normal verification sequence.
func TestVerifyRetrySucceedsOnSecondAttempt(t *testing.T) {
	repeatCalls := 0
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		if value == "attack" {
			repeatCalls++
			if repeatCalls == 1 {
				return models.ProbeResult{Err: errors.New("transient network blip")}
			}
			return models.ProbeResult{Body: "evidence-marker"}
		}
		return models.ProbeResult{Body: "safe"} // control value
	}
	check := func(pr models.ProbeResult) bool { return pr.Body == "evidence-marker" }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != Confirmed {
		t.Fatalf("expected the retry to recover from a single transient error and reach Confirmed, got %s (%s)", res.Status, res.Detail)
	}
	if repeatCalls != 2 {
		t.Fatalf("expected exactly 2 attempts at the repeat probe (1 failure + 1 retry), got %d", repeatCalls)
	}
}

// TestVerifyControlProbeErrorIsInconclusiveNotConfirmed is the regression
// test for the fix to the previous fall-through bug: if the control probe
// cannot be completed even after a bounded retry, the false-positive check
// never ran, so the result must not silently become Confirmed.
func TestVerifyControlProbeErrorIsInconclusiveNotConfirmed(t *testing.T) {
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		if value == "attack" {
			return models.ProbeResult{Body: "evidence-marker"}
		}
		return models.ProbeResult{Err: errors.New("control probe network failure")}
	}
	check := func(pr models.ProbeResult) bool { return pr.Body == "evidence-marker" }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != Inconclusive {
		t.Fatalf("expected Inconclusive when the control probe fails (false-positive check could not run), got %s (%s)", res.Status, res.Detail)
	}
	if res.Confidence != ConfidenceMedium {
		t.Fatalf("expected MEDIUM confidence (repeat reproduced, control unknown), got %s", res.Confidence)
	}
}

// TestVerifyNeverStarted covers the edge case where verification could not
// even begin (no Prober or no evidence check supplied). This must be
// Inconclusive with NONE confidence - distinct in cause from a repeat probe
// that ran and failed (TestVerifyInconclusiveOnProbeError), but sharing the
// same Status and Confidence outcome. Neither RepeatProbe nor ControlProbe
// should be populated, since no probe was ever attempted.
func TestVerifyNeverStarted(t *testing.T) {
	check := func(pr models.ProbeResult) bool { return true }
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Body: "should never be called"}
	}

	cases := []struct {
		name          string
		prober        Prober
		evidenceCheck func(models.ProbeResult) bool
	}{
		{"nil prober", nil, check},
		{"nil evidence check", prober, nil},
		{"both nil", nil, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", c.evidenceCheck, c.prober)
			if res.Status != Inconclusive {
				t.Fatalf("expected Inconclusive when verification cannot start, got %s (%s)", res.Status, res.Detail)
			}
			if res.Confidence != ConfidenceNone {
				t.Fatalf("expected NONE confidence when verification never started, got %s", res.Confidence)
			}
			if res.ConfidenceReason == "" {
				t.Fatal("expected a non-empty confidence reason")
			}
			if res.RepeatProbe != nil || res.ControlProbe != nil {
				t.Fatalf("expected no probes to have been attempted, got RepeatProbe=%v ControlProbe=%v", res.RepeatProbe, res.ControlProbe)
			}
		})
	}
}

// TestEvaluateConfidence_TableDriven is the single consolidated table
// covering every Status/repeatReproduced combination evaluateConfidence
// currently handles, including the default branch for Status values Verify
// itself never returns (Likely, Unverified) - locking in today's defined
// behavior for those values without expanding pkg/verification's
// responsibility to actually produce them.
//
// It also doubles as the explicit determinism/reproducibility check
// required by the confidence design: evaluateConfidence is invoked twice
// per case and both calls must agree exactly.
func TestEvaluateConfidence_TableDriven(t *testing.T) {
	cases := []struct {
		name             string
		status           Status
		repeatReproduced bool
		wantConfidence   Confidence
	}{
		{"Confirmed", Confirmed, true, ConfidenceHigh},
		{"FalsePositive", FalsePositive, true, ConfidenceHigh},
		{"Potential", Potential, false, ConfidenceLow},
		{"Inconclusive, repeat probe failed", Inconclusive, false, ConfidenceNone},
		{"Inconclusive, control probe failed after repeat reproduced", Inconclusive, true, ConfidenceMedium},
		{"Likely (Verify never returns this; locks default branch)", Likely, false, ConfidenceNone},
		{"Unverified (Verify never returns this; locks default branch)", Unverified, false, ConfidenceNone},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotConf1, gotReason1 := evaluateConfidence(c.status, c.repeatReproduced)
			if gotConf1 != c.wantConfidence {
				t.Fatalf("evaluateConfidence(%s, %v) = %s, want %s", c.status, c.repeatReproduced, gotConf1, c.wantConfidence)
			}
			if gotReason1 == "" {
				t.Fatal("expected a non-empty confidence reason")
			}

			// Reproducibility: identical inputs must yield an identical
			// result on a second, independent call - no hidden state, no
			// randomness, no time dependence.
			gotConf2, gotReason2 := evaluateConfidence(c.status, c.repeatReproduced)
			if gotConf2 != gotConf1 || gotReason2 != gotReason1 {
				t.Fatalf("evaluateConfidence(%s, %v) is not reproducible: first call = (%s, %q), second call = (%s, %q)",
					c.status, c.repeatReproduced, gotConf1, gotReason1, gotConf2, gotReason2)
			}
		})
	}
}
