package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"arfa/pkg/detectors"
	"arfa/pkg/models"
	"arfa/pkg/report"
)

// TestScan_ConfidenceAndEvidenceSurviveReportOutput is the full-path
// regression test for the Verification -> Evidence -> Finding -> Confidence
// -> Reporting flow (ARCHITECTURE.md §14): it runs a real Scan() against a
// live httptest server (exercising the real detector, real Verify(), and
// real verification.Cache - none of it mocked), then feeds the resulting
// models.ScanResult straight into the real pkg/report.JSON and
// pkg/report.HTML writers, and finally reads the written files back off
// disk. This is the missing link between the existing scanner-level tests
// (which only assert on the in-memory ScanResult) and the existing
// report-level tests (which only assert on a hand-built models.Finding):
// neither, on its own, proves that what Scan() actually produces is what
// ends up on disk for a human or downstream consumer to read.
func TestScan_ConfidenceAndEvidenceSurviveReportOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" {
			w.Write([]byte("<html><body>" + q + "</body></html>"))
			return
		}
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding from the real scan, got %d", len(result.Findings))
	}
	scanned := result.Findings[0]
	if scanned.VerificationConfidence != "HIGH" || scanned.EvidenceDetail == nil {
		t.Fatalf("test precondition failed: expected a real CONFIRMED/HIGH finding with EvidenceDetail from Scan() itself, got %+v", scanned)
	}
	wantHash := scanned.EvidenceDetail.ResponseHash
	wantReason := scanned.VerificationConfidenceReason

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "scan_results.json")
	htmlPath := filepath.Join(dir, "scan_report.html")

	if err := report.JSON(jsonPath, result); err != nil {
		t.Fatalf("report.JSON() error: %v", err)
	}
	if err := report.HTML(htmlPath, result); err != nil {
		t.Fatalf("report.HTML() error: %v", err)
	}

	// --- JSON leg: the exact values Scan() produced must round-trip
	// unchanged through the real file write/read, not just survive an
	// in-memory json.Marshal call.
	jb, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Findings []struct {
			VerificationStatus           string `json:"verification_status"`
			VerificationConfidence       string `json:"verification_confidence"`
			VerificationConfidenceReason string `json:"verification_confidence_reason"`
			EvidenceDetail               struct {
				ResponseHash      string   `json:"response_hash"`
				VerificationTrace []string `json:"verification_trace"`
			} `json:"evidence_detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(jb, &decoded); err != nil {
		t.Fatalf("failed to unmarshal report.JSON() output: %v", err)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding in the written JSON report, got %d", len(decoded.Findings))
	}
	jf := decoded.Findings[0]
	if jf.VerificationStatus != "CONFIRMED" {
		t.Fatalf("VerificationStatus did not survive to the JSON file: got %q", jf.VerificationStatus)
	}
	if jf.VerificationConfidence != "HIGH" {
		t.Fatalf("VerificationConfidence did not survive to the JSON file: got %q", jf.VerificationConfidence)
	}
	if jf.VerificationConfidenceReason != wantReason {
		t.Fatalf("VerificationConfidenceReason did not survive to the JSON file unchanged: got %q, want %q", jf.VerificationConfidenceReason, wantReason)
	}
	if jf.EvidenceDetail.ResponseHash != wantHash {
		t.Fatalf("EvidenceDetail.ResponseHash did not survive to the JSON file unchanged: got %q, want %q", jf.EvidenceDetail.ResponseHash, wantHash)
	}
	if len(jf.EvidenceDetail.VerificationTrace) == 0 {
		t.Fatal("EvidenceDetail.VerificationTrace did not survive to the JSON file")
	}

	// --- HTML leg: the same real values must appear in the rendered,
	// human-readable report, not just in the machine-readable JSON.
	hb, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	html := string(hb)
	for _, want := range []string{"Verification Confidence", "HIGH", wantReason, "Evidence Detail", wantHash} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected the real scan's data (%q) to appear in the rendered HTML report, but it did not", want)
		}
	}
}

// TestScan_FalsePositiveConfidenceSurvivesReportOutput exercises the other
// side of the Confidence model through the same full real path: a
// FalsePositive verification outcome (also ConfidenceHigh, per
// evaluateConfidence - see ADR 0001) must reach the report exactly as
// CONFIRMED does, not be silently dropped or downgraded on the way to disk.
func TestScan_FalsePositiveConfidenceSurvivesReportOutput(t *testing.T) {
	// The XSS marker is present on every response, including the benign
	// control value, so the control probe's evidence check also fires -
	// this is exactly the FalsePositive path in Verify().
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><xsstestmarker><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	reg := detectors.NewRegistry(detectors.XSS{})
	s := New(cfg, reg)
	s.payloads = map[string][]models.Payload{
		"XSS": {{ID: "t1", Category: "XSS", Value: "<xsstestmarker>"}},
	}

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].VerificationStatus != "FALSE_POSITIVE" {
		t.Fatalf("test precondition failed: expected FALSE_POSITIVE from Scan() itself, got %s", result.Findings[0].VerificationStatus)
	}
	if result.Findings[0].VerificationConfidence != "HIGH" {
		t.Fatalf("test precondition failed: expected HIGH confidence for FALSE_POSITIVE (see ADR 0001), got %s", result.Findings[0].VerificationConfidence)
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "scan_results.json")
	if err := report.JSON(jsonPath, result); err != nil {
		t.Fatalf("report.JSON() error: %v", err)
	}
	jb, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Findings []struct {
			VerificationStatus     string `json:"verification_status"`
			VerificationConfidence string `json:"verification_confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(jb, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding in the written JSON report, got %d", len(decoded.Findings))
	}
	if decoded.Findings[0].VerificationStatus != "FALSE_POSITIVE" {
		t.Fatalf("VerificationStatus=FALSE_POSITIVE did not survive to the JSON file: got %q", decoded.Findings[0].VerificationStatus)
	}
	if decoded.Findings[0].VerificationConfidence != "HIGH" {
		t.Fatalf("VerificationConfidence=HIGH for a FALSE_POSITIVE finding did not survive to the JSON file: got %q", decoded.Findings[0].VerificationConfidence)
	}
}

// TestScan_EmptyFindingsOmitsVerificationFieldsInReportOutput closes the
// remaining real-path gap: the additive/omitempty contract for
// VerificationConfidence/VerificationConfidenceReason/EvidenceDetail is
// already covered against a hand-built fixture in
// pkg/report.TestJSON_OmitsEmptyConfidenceAndEvidenceFields, but that does
// not prove the same holds for a real Scan() that produces zero findings
// at all (envelope-level omission, not just a single empty-verification
// finding). This test drives a real Scan() against a target with nothing
// to detect, then confirms the written JSON report is a valid, empty
// envelope with no verification keys leaked into it.
func TestScan_EmptyFindingsOmitsVerificationFieldsInReportOutput(t *testing.T) {
	// A static page with no reflected parameter and no <input> tag: the
	// crawler falls back to the generic parameter guess list, every probe
	// returns the same non-reflecting body, and no detector fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>static, nothing reflected here</body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("test precondition failed: expected 0 findings from a static, non-reflecting page, got %d", len(result.Findings))
	}

	path := filepath.Join(t.TempDir(), "scan_results.json")
	if err := report.JSON(path, result); err != nil {
		t.Fatalf("report.JSON() error: %v", err)
	}
	jb, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	js := string(jb)

	if !strings.Contains(js, `"schema_version": "arfa.scan/v1"`) {
		t.Fatalf("expected schema_version marker in the written report, got:\n%s", js)
	}
	if !strings.Contains(js, `"findings": []`) {
		t.Fatalf("expected an empty findings array in the written report, got:\n%s", js)
	}
	for _, key := range []string{"verification_confidence", "verification_confidence_reason", "evidence_detail"} {
		if strings.Contains(js, "\""+key+"\"") {
			t.Fatalf("expected %q to be absent from a report with zero findings, but it was present:\n%s", key, js)
		}
	}
}
