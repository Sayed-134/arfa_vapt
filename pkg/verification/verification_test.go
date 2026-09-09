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
