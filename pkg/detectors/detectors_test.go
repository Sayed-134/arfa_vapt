package detectors

import (
	"arfa/pkg/models"
	"context"
	"net/http"
	"strings"
	"testing"
)

func fakeProbe(body string, headers http.Header) Probe {
	return func(context.Context, string, string, map[string]string, models.Payload) models.ProbeResult {
		return models.ProbeResult{URL: "http://test", Status: 200, Body: body, Headers: headers}
	}
}

func TestLFINeedsRelevantPayload(t *testing.T) {
	d := LFI{}
	ep := models.Endpoint{URL: "http://test/?file=x", Method: "GET", Parameters: []string{"file"}}
	p := models.Payload{Category: "LFI", Value: "hello"}
	if got := d.Detect(context.Background(), ep, p, fakeProbe("root:x:0:0", nil)); len(got) != 0 {
		t.Fatalf("false positive: got %d", len(got))
	}
}

func TestXXENeedsXMLPayload(t *testing.T) {
	d := XXE{}
	ep := models.Endpoint{URL: "http://test/?xml=x", Method: "GET", Parameters: []string{"xml"}}
	p := models.Payload{Category: "XXE", Value: "hello"}
	if got := d.Detect(context.Background(), ep, p, fakeProbe("xxe-marker", nil)); len(got) != 0 {
		t.Fatalf("false positive: got %d", len(got))
	}
}

// --- TD #10: XSS CONFIRMED semantics ----------------------------------------

// TestXSSImplementsCaveatProvider is a compile-time-style regression guard:
// if XSS ever stops implementing CaveatProvider, this fails loudly instead
// of the caveat silently disappearing from every future CONFIRMED XSS
// finding.
func TestXSSImplementsCaveatProvider(t *testing.T) {
	var d Detector = XSS{}
	if _, ok := d.(CaveatProvider); !ok {
		t.Fatal("expected XSS to implement CaveatProvider (TD #10 regression)")
	}
}

// TestXSSConfirmationCaveatWording locks in the exact substance of the TD #10
// clarification: the caveat text must state plainly that CONFIRMED reflects
// reproducible server-side reflection, and must explicitly deny that it
// proves JavaScript execution. Wording may be refined later, but these two
// substantive claims are the semantics being pinned down.
func TestXSSConfirmationCaveatWording(t *testing.T) {
	caveat := XSS{}.ConfirmationCaveat()
	if caveat == "" {
		t.Fatal("expected a non-empty confirmation caveat")
	}
	if !strings.Contains(caveat, "reflect") {
		t.Fatalf("expected the caveat to describe reflection-based evidence, got: %q", caveat)
	}
	if !strings.Contains(strings.ToLower(caveat), "does not prove") && !strings.Contains(strings.ToLower(caveat), "not prove") {
		t.Fatalf("expected the caveat to explicitly deny proof of execution, got: %q", caveat)
	}
	if !strings.Contains(strings.ToLower(caveat), "javascript") {
		t.Fatalf("expected the caveat to name JavaScript execution specifically, got: %q", caveat)
	}
}

// TestOtherDetectorsDoNotImplementCaveatProvider confirms TD #10 is scoped
// to XSS only, as instructed: no other existing detector gains a caveat as
// a side effect of adding the CaveatProvider interface.
func TestOtherDetectorsDoNotImplementCaveatProvider(t *testing.T) {
	others := []Detector{SQLi{}, LFI{}, RCE{}, SSTI{}, SSRF{}, XXE{}, CRLF{}, Redirect{}}
	for _, d := range others {
		if _, ok := d.(CaveatProvider); ok {
			t.Fatalf("expected %s to NOT implement CaveatProvider (TD #10 is scoped to XSS only)", d.Category())
		}
	}
}
