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
		t.Fatalf("expected exactly 2 verification probes (repeat + control), got %d", calls)
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
}

func TestVerifyInconclusiveOnProbeError(t *testing.T) {
	prober := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Err: errors.New("boom")}
	}
	check := func(pr models.ProbeResult) bool { return true }

	res := Verify(context.Background(), models.Endpoint{URL: "http://x"}, "id", "attack", check, prober)
	if res.Status != Inconclusive {
		t.Fatalf("expected Inconclusive, got %s (%s)", res.Status, res.Detail)
	}
}
