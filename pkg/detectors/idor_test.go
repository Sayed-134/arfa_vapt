package detectors

import (
	"arfa/pkg/models"
	"context"
	"testing"
)

func TestScanIDORFindsDivergentNeighbour(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/profile?id=100", Method: "GET", Parameters: []string{"id"}}
	probe := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		switch value {
		case "100":
			return models.ProbeResult{Status: 200, Body: "profile for user 100 with a fair amount of content here"}
		case "99":
			return models.ProbeResult{Status: 200, Body: "profile for user 99 with a totally different amount of content here padded out"}
		default:
			return models.ProbeResult{Status: 200, Body: "not found"}
		}
	}
	got := ScanIDOR(context.Background(), ep, probe)
	found99 := false
	for _, f := range got {
		if f.Payload == "99" {
			found99 = true
			if f.VerificationStatus != Unverified {
				t.Fatalf("expected IDOR findings to be UNVERIFIED, got %s", f.VerificationStatus)
			}
		}
	}
	if !found99 {
		t.Fatalf("expected a finding for the decremented neighbour, got %d findings: %+v", len(got), got)
	}
}

func TestScanIDORSkipsNonNumericParam(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/search?q=hello", Method: "GET", Parameters: []string{"q"}}
	probe := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		t.Fatalf("probe should not be called for a non-numeric parameter")
		return models.ProbeResult{}
	}
	got := ScanIDOR(context.Background(), ep, probe)
	if len(got) != 0 {
		t.Fatalf("expected no findings, got %d", len(got))
	}
}

func TestScanIDORIgnoresDenialResponses(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/profile?id=5", Method: "GET", Parameters: []string{"id"}}
	probe := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		if value == "5" {
			return models.ProbeResult{Status: 200, Body: "profile for user 5"}
		}
		return models.ProbeResult{Status: 200, Body: "Access Denied"}
	}
	got := ScanIDOR(context.Background(), ep, probe)
	if len(got) != 0 {
		t.Fatalf("expected no findings for denial-page neighbours, got %d", len(got))
	}
}
