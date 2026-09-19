package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"arfa/pkg/detectors"
)

// TD #16 — Payload corpus reproducibility/versioning.
//
// These tests confirm the corpus identity computed by LoadPayloads is
// actually threaded through to the scan result envelope (the "ربط corpus
// identity بالـscan الذي استخدمه" / "linked to the scan that used it"
// requirement), without affecting payload selection or detector behavior.

func writeTinyCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "XSS Injection")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("<xsstestmarker>\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestScan_CorpusFingerprintPopulatedWhenPayloadsLoaded confirms a real
// Scan() result carries a non-empty CorpusFingerprint once LoadPayloads has
// run, and that the same corpus produces the same fingerprint across two
// independent scanners/scans.
func TestScan_CorpusFingerprintPopulatedWhenPayloadsLoaded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>no reflection here</body></html>`))
	}))
	defer srv.Close()

	root := writeTinyCorpus(t)
	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}

	reg1 := detectors.NewRegistry(detectors.XSS{})
	s1 := New(cfg, reg1)
	if err := s1.LoadPayloads(root); err != nil {
		t.Fatalf("LoadPayloads error: %v", err)
	}
	result1, err := s1.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result1.CorpusFingerprint == "" {
		t.Fatal("expected a non-empty CorpusFingerprint once LoadPayloads has run")
	}

	reg2 := detectors.NewRegistry(detectors.XSS{})
	s2 := New(cfg, reg2)
	if err := s2.LoadPayloads(root); err != nil {
		t.Fatalf("LoadPayloads error: %v", err)
	}
	result2, err := s2.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.CorpusFingerprint != result1.CorpusFingerprint {
		t.Fatalf("expected the same corpus to produce the same CorpusFingerprint across independent scans, got %q and %q", result1.CorpusFingerprint, result2.CorpusFingerprint)
	}
}

// TestScan_CorpusFingerprintEmptyWhenPayloadsNeverLoaded confirms the
// additive/omitempty contract: a Scanner on which LoadPayloads was never
// called (e.g. mirroring a -preflight-only invocation, or the existing
// test helpers in this package that set s.payloads directly) reports an
// empty CorpusFingerprint rather than a fabricated one.
func TestScan_CorpusFingerprintEmptyWhenPayloadsNeverLoaded(t *testing.T) {
	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg) // sets s.payloads directly; never calls LoadPayloads

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>no reflection here</body></html>`))
	}))
	defer srv.Close()

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CorpusFingerprint != "" {
		t.Fatalf("expected an empty CorpusFingerprint when LoadPayloads was never called, got %q", result.CorpusFingerprint)
	}
}
