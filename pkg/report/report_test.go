package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arfa/pkg/models"
)

func sampleFinding() models.Finding {
	return models.Finding{
		ID:                           "f1",
		Category:                     "XSS",
		Name:                         "Reflected XSS",
		Severity:                     "High",
		Confidence:                   "HIGH", // detector's own initial confidence field
		Endpoint:                     "http://x/search",
		Parameter:                    "q",
		Evidence:                     "payload reflected",
		VerificationStatus:           "CONFIRMED",
		VerificationDetail:           "evidence reproduced on independent probe and absent for a benign control value",
		VerificationConfidence:       "HIGH",
		VerificationConfidenceReason: "evidence reproduced on an independent repeat probe and was absent for a benign control value",
		EvidenceDetail: &models.Evidence{
			Timestamp:         "2026-09-10T12:00:00Z",
			Endpoint:          "http://x/search",
			Parameter:         "q",
			Category:          "XSS",
			RequestMethod:     "GET",
			RequestURL:        "http://x/search?q=%3Cxsstestmarker%3E",
			ResponseStatus:    200,
			ResponseSnippet:   "<html><body><xsstestmarker></body></html>",
			ResponseHash:      "deadbeef",
			VerificationTrace: []string{"repeat probe: status 200, 41 byte response", "verdict: CONFIRMED - evidence reproduced"},
		},
	}
}

// TestJSON_PreservesVerificationConfidenceAndEvidenceDetail locks in the
// "Final JSON Report" contract from ARCHITECTURE.md §13/§14: fields added
// by Confidence Evaluation and Milestone 2's structured Evidence must
// survive the JSON round trip unchanged, since report.JSON performs a
// plain struct marshal with no field allowlist.
func TestJSON_PreservesVerificationConfidenceAndEvidenceDetail(t *testing.T) {
	r := models.ScanResult{
		SchemaVersion: "arfa.scan/v1",
		Target:        "http://x",
		Findings:      []models.Finding{sampleFinding()},
	}
	path := filepath.Join(t.TempDir(), "scan_results.json")
	if err := JSON(path, r); err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	findings, ok := decoded["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding in decoded JSON, got %+v", decoded["findings"])
	}
	f := findings[0].(map[string]any)

	if f["verification_confidence"] != "HIGH" {
		t.Fatalf("expected verification_confidence=HIGH in JSON output, got %v", f["verification_confidence"])
	}
	if f["verification_confidence_reason"] != "evidence reproduced on an independent repeat probe and was absent for a benign control value" {
		t.Fatalf("verification_confidence_reason did not survive the JSON round trip: %v", f["verification_confidence_reason"])
	}
	ev, ok := f["evidence_detail"].(map[string]any)
	if !ok {
		t.Fatalf("expected evidence_detail object in JSON output, got %v", f["evidence_detail"])
	}
	if ev["response_hash"] != "deadbeef" {
		t.Fatalf("evidence_detail.response_hash did not survive the JSON round trip: %v", ev["response_hash"])
	}
	trace, ok := ev["verification_trace"].([]any)
	if !ok || len(trace) != 2 {
		t.Fatalf("expected 2 verification_trace entries to survive the JSON round trip, got %v", ev["verification_trace"])
	}
}

// TestJSON_OmitsEmptyConfidenceAndEvidenceFields confirms the additive/
// omitempty contract: a finding produced without verification (e.g. an
// IDOR heuristic finding, VerificationConfidence left "") must not gain
// spurious empty keys in the JSON output, preserving compatibility for
// existing consumers.
func TestJSON_OmitsEmptyConfidenceAndEvidenceFields(t *testing.T) {
	r := models.ScanResult{
		SchemaVersion: "arfa.scan/v1",
		Target:        "http://x",
		Findings: []models.Finding{{
			ID:                 "f2",
			Category:           "IDOR",
			VerificationStatus: "UNVERIFIED",
			// VerificationConfidence, VerificationConfidenceReason, EvidenceDetail
			// intentionally left at their zero values.
		}},
	}
	path := filepath.Join(t.TempDir(), "scan_results.json")
	if err := JSON(path, r); err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, key := range []string{"verification_confidence", "verification_confidence_reason", "evidence_detail"} {
		if strings.Contains(s, "\""+key+"\"") {
			t.Fatalf("expected %q to be omitted from JSON when empty, but it was present:\n%s", key, s)
		}
	}
}

// TestHTML_RendersVerificationConfidenceAndEvidenceDetail is the
// human-readable-report counterpart to the JSON test above: verifies the
// gap identified from ARCHITECTURE.md §13 ("Evidence Attachments",
// "Confidence Information") is actually closed in the rendered HTML, not
// just present in the underlying data.
func TestHTML_RendersVerificationConfidenceAndEvidenceDetail(t *testing.T) {
	r := models.ScanResult{Target: "http://x", Mode: "quick", Findings: []models.Finding{sampleFinding()}}
	path := filepath.Join(t.TempDir(), "scan_report.html")
	if err := HTML(path, r); err != nil {
		t.Fatalf("HTML() error: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)

	for _, want := range []string{
		"Verification Confidence",
		"HIGH", // the VerificationConfidence value itself
		"evidence reproduced on an independent repeat probe and was absent for a benign control value", // ConfidenceReason
		"Evidence Detail",
		"deadbeef", // ResponseHash
		"repeat probe: status 200, 41 byte response", // a VerificationTrace entry
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected rendered HTML to contain %q, but it did not", want)
		}
	}
}

// TestHTML_NilSafeWhenVerificationDataAbsent ensures findings without
// verification confidence or structured evidence (e.g. IDOR heuristic
// findings, or findings produced before this increment) render without
// panicking and without emitting the new sections at all - html/template
// treats a nil *Evidence and an empty string correctly with {{if}}, but
// this is asserted explicitly rather than assumed.
func TestHTML_NilSafeWhenVerificationDataAbsent(t *testing.T) {
	r := models.ScanResult{
		Target: "http://x",
		Mode:   "quick",
		Findings: []models.Finding{{
			ID:                 "f3",
			Category:           "IDOR",
			Name:               "Possible IDOR",
			Severity:           "Medium",
			VerificationStatus: "UNVERIFIED",
			Evidence:           "numeric id mutation returned a different owner's record",
			// VerificationConfidence, VerificationConfidenceReason, EvidenceDetail: zero values.
		}},
	}
	path := filepath.Join(t.TempDir(), "scan_report.html")
	if err := HTML(path, r); err != nil {
		t.Fatalf("HTML() error (should be nil-safe): %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, unwanted := range []string{"Verification Confidence", "Evidence Detail"} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("did not expect %q to be rendered for a finding with no verification confidence/evidence data", unwanted)
		}
	}
}
