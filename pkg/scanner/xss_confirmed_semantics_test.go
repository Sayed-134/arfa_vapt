package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"arfa/pkg/detectors"
	"arfa/pkg/models"
)

// TestScan_ConfirmedXSSCarriesVerificationCaveat is the end-to-end
// regression test for TD #10: a real Scan() against a real reflecting
// endpoint (same pattern as the existing CONFIRMED XSS tests) must produce
// a finding whose VerificationCaveat is populated, without altering
// VerificationStatus, VerificationDetail or VerificationConfidence.
func TestScan_ConfirmedXSSCarriesVerificationCaveat(t *testing.T) {
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
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.VerificationStatus != "CONFIRMED" {
		t.Fatalf("test precondition failed: expected CONFIRMED, got %s", f.VerificationStatus)
	}
	if f.VerificationCaveat == "" {
		t.Fatal("expected VerificationCaveat to be populated for a CONFIRMED XSS finding (TD #10)")
	}
	wantDetail := "evidence reproduced on independent probe and absent for a benign control value"
	if f.VerificationDetail != wantDetail {
		t.Fatalf("VerificationDetail must remain unchanged by TD #10, got %q", f.VerificationDetail)
	}
	if f.VerificationConfidence != "HIGH" {
		t.Fatalf("VerificationConfidence must remain unchanged by TD #10, got %q", f.VerificationConfidence)
	}
}

// TestScan_NonConfirmedXSSHasNoVerificationCaveat confirms the caveat is
// scoped strictly to CONFIRMED, not to the XSS category in general: a
// FALSE_POSITIVE XSS finding (the marker also fires on the benign control
// value) must not carry a caveat that was only ever meant to qualify a
// CONFIRMED claim.
func TestScan_NonConfirmedXSSHasNoVerificationCaveat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><xsstestmarker><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.VerificationStatus != "FALSE_POSITIVE" {
		t.Fatalf("test precondition failed: expected FALSE_POSITIVE, got %s", f.VerificationStatus)
	}
	if f.VerificationCaveat != "" {
		t.Fatalf("expected no VerificationCaveat for a non-CONFIRMED status, got %q", f.VerificationCaveat)
	}
}

// TestScan_ConfirmedSQLiHasNoVerificationCaveat confirms TD #10 is isolated
// to XSS, end to end: a CONFIRMED SQLi finding from a real Scan() must not
// pick up a caveat, since SQLi does not implement detectors.CaveatProvider.
func TestScan_ConfirmedSQLiHasNoVerificationCaveat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "'" {
			w.Write([]byte(`<html><body>you have an error in your sql syntax</body></html>`))
			return
		}
		w.Write([]byte(`<html><body><input name="id"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	reg := detectors.NewRegistry(detectors.SQLi{})
	s := New(cfg, reg)
	s.payloads = map[string][]models.Payload{
		"SQLi": {{ID: "t1", Category: "SQLi", Value: "'"}},
	}

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.VerificationStatus != "CONFIRMED" {
		t.Fatalf("test precondition failed: expected CONFIRMED, got %s", f.VerificationStatus)
	}
	if f.VerificationCaveat != "" {
		t.Fatalf("expected no VerificationCaveat for SQLi (TD #10 is scoped to XSS only), got %q", f.VerificationCaveat)
	}
}
