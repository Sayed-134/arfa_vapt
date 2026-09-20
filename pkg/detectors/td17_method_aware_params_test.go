package detectors

import (
	"context"
	"reflect"
	"testing"

	"arfa/pkg/models"
)

// TD #17 — Method-aware parameter selection in detectors
// (see PHASE_4_TD_SPECS.md). These tests cover params()'s Required Tests
// #1-#8; the remaining required tests (#9 GET regression, #10 TD #5 noise
// filter, #11 XSS/SQLi/LFI GET behavior, #12 race/concurrency, #13 full
// suite) are covered by the existing pkg/detectors and pkg/scanner test
// suites, which this change does not modify.

func TestParams_GETWithParametersReturnsThem(t *testing.T) {
	ep := models.Endpoint{Method: "GET", Parameters: []string{"a", "b"}}
	got := params(ep)
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected GET with discovered Parameters to return them unchanged, got %v, want %v", got, want)
	}
}

func TestParams_GETWithEmptyParametersUsesFallback(t *testing.T) {
	ep := models.Endpoint{Method: "GET"}
	got := params(ep)
	want := []string{"q", "id", "search", "page", "url", "file", "name"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected the unchanged 7-entry GET fallback list, got %v, want %v", got, want)
	}
}

func TestParams_POSTWithFormParametersReturnsThem(t *testing.T) {
	ep := models.Endpoint{Method: "POST", FormParameters: []string{"x"}}
	got := params(ep)
	want := []string{"x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected POST with discovered FormParameters to return them, got %v, want %v", got, want)
	}
}

func TestParams_POSTWithEmptyFormParametersReturnsZero(t *testing.T) {
	ep := models.Endpoint{Method: "POST"}
	got := params(ep)
	if len(got) != 0 {
		t.Fatalf("expected zero parameters for a POST endpoint with no FormParameters (no fallback), got %v", got)
	}
}

func TestParams_POSTNeverUsesGETFallbackList(t *testing.T) {
	ep := models.Endpoint{Method: "POST"} // FormParameters empty
	got := params(ep)
	for _, fallback := range []string{"q", "id", "search", "page", "url", "file", "name"} {
		for _, p := range got {
			if p == fallback {
				t.Fatalf("did not expect the GET-oriented fallback parameter %q for a POST endpoint, got %v", fallback, got)
			}
		}
	}
}

func TestParams_GETNeverUsesFormParameters(t *testing.T) {
	ep := models.Endpoint{Method: "GET", FormParameters: []string{"should-not-appear"}}
	got := params(ep)
	// GET's own Parameters is empty, so it must fall back to the GET
	// guess list - never read FormParameters.
	for _, p := range got {
		if p == "should-not-appear" {
			t.Fatalf("did not expect a GET endpoint to read FormParameters, got %v", got)
		}
	}
	want := []string{"q", "id", "search", "page", "url", "file", "name"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected the unchanged GET fallback list, got %v, want %v", got, want)
	}
}

// TestScan_POSTFindingParameterMatchesSentParameter is the Detect-level
// regression test (Required Test #7/#8): a POST endpoint with a single
// FormParameter must produce exactly one finding, whose Parameter matches
// the field that was actually sent - not a fallback-list label.
func TestScan_POSTFindingParameterMatchesSentParameter(t *testing.T) {
	d := XSS{}
	ep := models.Endpoint{URL: "http://test/submit", Method: "POST", FormParameters: []string{"comment"}}
	p := models.Payload{Category: "XSS", Value: "<xsstestmarker>"}

	got := d.Detect(context.Background(), ep, p, fakeProbe("<xsstestmarker>", nil))
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding for a single-field POST endpoint, got %d: %+v", len(got), got)
	}
	if got[0].Parameter != "comment" {
		t.Fatalf("expected the finding's Parameter to match the sent field %q, got %q", "comment", got[0].Parameter)
	}
}

// TestScan_POSTWithNoFormParametersProducesNoFindings confirms a POST
// endpoint with nothing to mutate never falls back to the GET guess list
// and produces no findings, even when the probe would otherwise fire.
func TestScan_POSTWithNoFormParametersProducesNoFindings(t *testing.T) {
	d := XSS{}
	ep := models.Endpoint{URL: "http://test/submit", Method: "POST"} // no FormParameters
	p := models.Payload{Category: "XSS", Value: "<xsstestmarker>"}

	got := d.Detect(context.Background(), ep, p, fakeProbe("<xsstestmarker>", nil))
	if len(got) != 0 {
		t.Fatalf("expected 0 findings for a POST endpoint with no FormParameters, got %d: %+v", len(got), got)
	}
}
