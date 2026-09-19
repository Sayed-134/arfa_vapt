package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"arfa/pkg/models"
)

// TestScan_EvidenceRecordsProbeInjectedQueryParamNotEndpointOriginalQuery is
// the direct regression test for TD #9's Required Behavior #2/Required Test
// #1: RequestQueryParams must record only the single parameter this probe
// injected - never any other query parameter already present on the
// endpoint's own URL.
func TestScan_EvidenceRecordsProbeInjectedQueryParamNotEndpointOriginalQuery(t *testing.T) {
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

	// The endpoint's own URL already carries an unrelated query parameter
	// ("other=1") that is not part of the discovered mutation surface.
	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: srv.URL + "/search?other=1", Method: "GET", Parameters: []string{"q"}},
	}, pages: 1}
	s.crawl = fc

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(result.Findings))
	}
	ev := result.Findings[0].EvidenceDetail
	if ev == nil {
		t.Fatal("expected EvidenceDetail to be populated")
	}
	if len(ev.RequestQueryParams) != 1 {
		t.Fatalf("expected exactly one probe-injected query param recorded, got %v", ev.RequestQueryParams)
	}
	if got := ev.RequestQueryParams.Get("q"); got == "" {
		t.Fatalf("expected RequestQueryParams to contain the mutated 'q' parameter, got %v", ev.RequestQueryParams)
	}
	if _, leaked := ev.RequestQueryParams["other"]; leaked {
		t.Fatalf("expected the endpoint's own original query parameter 'other' to never appear in RequestQueryParams, got %v", ev.RequestQueryParams)
	}
	if len(ev.RequestFormParams) != 0 {
		t.Fatalf("expected RequestFormParams to be empty for a GET probe, got %v", ev.RequestFormParams)
	}
}

// TestScan_EvidenceRecordsFormParamForPOST confirms the POST-transport
// mirror of the above: RequestFormParams records exactly the single
// mutated form field, and RequestQueryParams stays empty.
func TestScan_EvidenceRecordsFormParamForPOST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		x := r.PostFormValue("x")
		if x != "" {
			w.Write([]byte("<html><body>" + x + "</body></html>"))
			return
		}
		w.Write([]byte(`<html><body><input name="x"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: srv.URL + "/submit", Method: "POST", FormParameters: []string{"x"}},
	}, pages: 1}
	s.crawl = fc

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Note: pkg/detectors' own params() helper (unrelated to TD #9, not
	// modified here) falls back to a fixed 7-entry guess list whenever
	// ep.Parameters is empty - which it always is for a POST job (TD #2
	// puts the mutated field in FormParameters instead). Each of those 7
	// internal iterations re-checks the *same* cached probe result
	// against a different assumed (and, for POST, mostly fictitious)
	// Parameter label, so several Findings can result from one real POST
	// probe. This is pre-existing detector behavior, not a TD #9
	// regression - what TD #9 owns is that every one of those Findings'
	// EvidenceDetail is still built from the job's one real, correct
	// param/value (see buildEvidence's call site in scanner.go), so every
	// resulting finding's evidence agrees. See the delivered report notes
	// for this observation.
	if len(result.Findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	for _, f := range result.Findings {
		ev := f.EvidenceDetail
		if ev == nil {
			t.Fatal("expected EvidenceDetail to be populated")
		}
		if len(ev.RequestQueryParams) != 0 {
			t.Fatalf("expected RequestQueryParams to be empty for a POST probe, got %v", ev.RequestQueryParams)
		}
		if got := ev.RequestFormParams.Get("x"); got == "" {
			t.Fatalf("expected RequestFormParams to contain the mutated 'x' field, got %v", ev.RequestFormParams)
		}
		if len(ev.RequestFormParams) != 1 {
			t.Fatalf("expected exactly one form param recorded, got %v", ev.RequestFormParams)
		}
	}
}

// TestScan_EvidenceRequestHeadersReconstructed confirms RequestHeaders
// carries the deterministic, known-fixed header set (User-Agent, Accept,
// and Content-Type for POST-with-form-params) and nothing sensitive.
func TestScan_EvidenceRequestHeadersReconstructed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		x := r.PostFormValue("x")
		if x != "" {
			w.Write([]byte("<html><body>" + x + "</body></html>"))
			return
		}
		w.Write([]byte(`<html><body><input name="x"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)
	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: srv.URL + "/submit", Method: "POST", FormParameters: []string{"x"}},
	}, pages: 1}
	s.crawl = fc

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// See the note in TestScan_EvidenceRecordsFormParamForPOST: a POST job
	// can legitimately produce more than one Finding from pkg/detectors'
	// own pre-existing (TD #9-unrelated) params() fallback; every one of
	// them still carries the same, correctly-reconstructed EvidenceDetail.
	if len(result.Findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	ev := result.Findings[0].EvidenceDetail
	if ev == nil {
		t.Fatal("expected EvidenceDetail to be populated")
	}
	if ev.RequestHeaders["User-Agent"] != "Arfa-VAPT/1.0" {
		t.Fatalf("expected reconstructed User-Agent header, got %q", ev.RequestHeaders["User-Agent"])
	}
	if ev.RequestHeaders["Accept"] == "" {
		t.Fatal("expected a reconstructed Accept header")
	}
	if ev.RequestHeaders["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("expected reconstructed Content-Type for a POST-with-form-params probe, got %q", ev.RequestHeaders["Content-Type"])
	}
	for k := range ev.RequestHeaders {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") {
			t.Fatalf("did not expect a sensitive header name in the reconstructed set, got key %q", k)
		}
	}
}

// TestScan_EvidenceResponseHeadersRedacted is the scanner-level wiring
// proof that pkg/redact is actually applied to response headers before
// they enter Evidence: a Set-Cookie header from the real server must never
// appear raw, while an ordinary header is preserved unredacted.
func TestScan_EvidenceResponseHeadersRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=super-secret-value; HttpOnly")
		w.Header().Set("X-Test-Marker", "arfa-td9")
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
	ev := result.Findings[0].EvidenceDetail
	if ev == nil {
		t.Fatal("expected EvidenceDetail to be populated")
	}
	setCookie := ev.ResponseHeaders["Set-Cookie"]
	if setCookie != "[REDACTED]" {
		t.Fatalf("expected Set-Cookie to be redacted in ResponseHeaders, got %q", setCookie)
	}
	if strings.Contains(setCookie, "super-secret-value") {
		t.Fatal("raw cookie value leaked into ResponseHeaders")
	}
	if ev.ResponseHeaders["X-Test-Marker"] != "arfa-td9" {
		t.Fatalf("expected a non-sensitive response header to be preserved unredacted, got %q", ev.ResponseHeaders["X-Test-Marker"])
	}
}

// TestScan_EvidenceResponseBodyLengthSurvivesSnippetTruncation confirms
// ResponseBodyLength preserves the true full-body size even when
// ResponseSnippet itself is bounded to evidenceSnippetLimit.
func TestScan_EvidenceResponseBodyLengthSurvivesSnippetTruncation(t *testing.T) {
	longMarker := strings.Repeat("A", evidenceSnippetLimit+250)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" {
			// Reflect the payload plus padding so the full response body
			// comfortably exceeds evidenceSnippetLimit.
			w.Write([]byte("<html><body>" + q + longMarker + "</body></html>"))
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
	ev := result.Findings[0].EvidenceDetail
	if ev == nil {
		t.Fatal("expected EvidenceDetail to be populated")
	}
	if len(ev.ResponseSnippet) != evidenceSnippetLimit {
		t.Fatalf("expected ResponseSnippet truncated to evidenceSnippetLimit=%d, got %d bytes", evidenceSnippetLimit, len(ev.ResponseSnippet))
	}
	if ev.ResponseBodyLength <= evidenceSnippetLimit {
		t.Fatalf("expected ResponseBodyLength to reflect the full untruncated body (> %d), got %d", evidenceSnippetLimit, ev.ResponseBodyLength)
	}
}

// TestScan_ExistingEvidenceFieldsUnchangedByTD9 is a narrow regression
// guard: the pre-TD-#9 Evidence fields (RequestMethod, RequestURL,
// ResponseStatus, ResponseHash, VerificationTrace) must remain populated
// exactly as before - TD #9 is additive only.
func TestScan_ExistingEvidenceFieldsUnchangedByTD9(t *testing.T) {
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
	ev := result.Findings[0].EvidenceDetail
	if ev == nil {
		t.Fatal("expected EvidenceDetail to be populated")
	}
	if ev.RequestMethod != "GET" {
		t.Fatalf("expected RequestMethod=GET unchanged, got %q", ev.RequestMethod)
	}
	if ev.RequestURL == "" {
		t.Fatal("expected RequestURL to still be populated")
	}
	if ev.ResponseStatus != 200 {
		t.Fatalf("expected ResponseStatus=200 unchanged, got %d", ev.ResponseStatus)
	}
	if ev.ResponseHash == "" {
		t.Fatal("expected ResponseHash to still be populated")
	}
	if len(ev.VerificationTrace) == 0 {
		t.Fatal("expected VerificationTrace to still be populated for an XSS finding")
	}
}
