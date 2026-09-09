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

func newTestScanner(t *testing.T, cfg Config) *Scanner {
	t.Helper()
	reg := detectors.NewRegistry(detectors.XSS{})
	s := New(cfg, reg)
	s.payloads = map[string][]models.Payload{
		"XSS": {{ID: "t1", Category: "XSS", Value: "<xsstestmarker>"}},
	}
	return s
}

// --- 1. Bounded job scheduling -------------------------------------------

func TestScan_MaxJobsCapsSchedulingAndReportsIt(t *testing.T) {
	// No <input> tag and no "?" in the URL, so the crawler discovers zero
	// explicit parameters and falls back to the generic 5-parameter guess
	// list (q, id, search, page, url - see effectiveParams) for a single
	// endpoint. That naturally yields 5 jobs (1 detector x 1 payload x 5
	// params x 1 encoding); capping at 2 must produce exactly 2.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>static page, no form</body></html>`))
	}))
	defer srv.Close()
	cfg := Config{Workers: 4, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxJobs: 2}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Stats.JobsCapped {
		t.Fatal("expected JobsCapped=true when MaxJobs is below the natural job count")
	}
	if result.Stats.JobsPlanned != 2 {
		t.Fatalf("expected JobsPlanned=2 (the MaxJobs cap), got %d", result.Stats.JobsPlanned)
	}
	if result.Stats.Requests > 2 {
		t.Fatalf("expected at most 2 probe requests under the cap, got %d", result.Stats.Requests)
	}
}

func TestScan_UncappedReportsPlannedWithoutCapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stats.JobsCapped {
		t.Fatal("did not expect JobsCapped for a scan well under defaultMaxJobs")
	}
	if result.Stats.JobsPlanned == 0 {
		t.Fatal("expected JobsPlanned to be reported even when not capped")
	}
}

// --- 2. Interface substitution (adapter seam) -----------------------------

type fakeCrawler struct {
	eps   []models.Endpoint
	pages int
}

func (f fakeCrawler) Crawl(ctx context.Context, target string) ([]models.Endpoint, int, error) {
	return f.eps, f.pages, nil
}

type fakeTransport struct {
	calls  int
	body   string
	status int
}

func (f *fakeTransport) Do(ctx context.Context, method, rawURL string, params map[string]string) (string, int, http.Header, time.Duration, error) {
	f.calls++
	return f.body, f.status, http.Header{}, time.Millisecond, nil
}

func TestScan_UsesInjectedCrawlerAndTransportNotRealNetwork(t *testing.T) {
	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{{URL: "http://fake.invalid/page", Method: "GET", Parameters: []string{"q"}}}, pages: 1}
	ft := &fakeTransport{body: "<html><body><xsstestmarker></body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	// "http://fake.invalid" is not a resolvable/reachable host - if the
	// scanner actually tried the real network instead of the injected
	// fakes, this would either error or hang. Success here proves the
	// crawl+probe path went entirely through the injected adapters.
	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ft.calls == 0 {
		t.Fatal("expected the injected fake Transport to have been called at least once")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding from the injected fake response, got %d", len(result.Findings))
	}
}

// --- 3. Structured Evidence -------------------------------------------------

func TestScan_PopulatesStructuredEvidenceForConfirmedFinding(t *testing.T) {
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
	if f.EvidenceDetail == nil {
		t.Fatal("expected EvidenceDetail to be populated")
	}
	if f.EvidenceDetail.ResponseHash == "" {
		t.Fatal("expected a non-empty ResponseHash")
	}
	if len(f.EvidenceDetail.ResponseSnippet) > evidenceSnippetLimit {
		t.Fatalf("response snippet exceeded the redaction bound: %d bytes", len(f.EvidenceDetail.ResponseSnippet))
	}
	if len(f.EvidenceDetail.VerificationTrace) == 0 {
		t.Fatal("expected a non-empty verification trace for an XSS finding (XSS implements EvidenceChecker)")
	}
	if f.VerificationStatus != "CONFIRMED" {
		t.Fatalf("expected CONFIRMED given this endpoint reflects only the real payload, got %s", f.VerificationStatus)
	}
	if f.VerificationConfidence != "HIGH" {
		t.Fatalf("expected HIGH verification confidence for a CONFIRMED finding, got %q", f.VerificationConfidence)
	}
	if f.VerificationConfidenceReason == "" {
		t.Fatal("expected a non-empty verification confidence reason")
	}
}

// --- 6. Verification Result Cache -------------------------------------------

// TestScan_VerificationCacheAvoidsDuplicateProbesForIdenticalCandidate is the
// scanner-level regression test for the Verification Result Cache gap: two
// detectors that both fire an identical candidate (same category, endpoint,
// parameter and payload value) must only pay for one repeat+control
// verification sequence, not two, even though both candidates are detected
// and appear in coverage/reporting.
func TestScan_VerificationCacheAvoidsDuplicateProbesForIdenticalCandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" {
			w.Write([]byte("<html><body>" + q + "</body></html>"))
			return
		}
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 1, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	// Two independent XSS detector instances register the same category and
	// will each independently detect + attempt to verify the identical
	// candidate (same category/endpoint/param/payload value) against this
	// server, since both share the one XSS payload loaded below.
	reg := detectors.NewRegistry(detectors.XSS{}, detectors.XSS{})
	s := New(cfg, reg)
	s.payloads = map[string][]models.Payload{
		"XSS": {{ID: "t1", Category: "XSS", Value: "<xsstestmarker>"}},
	}

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Without a cache: 2 initial detect probes (one per detector instance)
	// + 2 verification sequences x 2 probes (repeat+control) each = 6.
	// With the cache, the second detector's identical candidate reuses the
	// first verification Result: 2 initial detect probes + 1 verification
	// sequence x 2 probes = 4.
	if result.Stats.Requests != 4 {
		t.Fatalf("expected exactly 4 requests (2 detect + 1 cached verification pair), got %d - cache is not preventing duplicate verification probes", result.Stats.Requests)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the two identical candidates to dedup to 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].VerificationStatus != "CONFIRMED" {
		t.Fatalf("expected the cached verification result to still be CONFIRMED, got %s", result.Findings[0].VerificationStatus)
	}
}

// --- 4. Coverage + planner wiring ------------------------------------------

func TestScan_CoverageAndNextActionsArePopulated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Coverage) == 0 {
		t.Fatal("expected at least one coverage entry")
	}
	// No payload reflects, so the XSS/q cell must resolve to Attempted (a
	// probe ran, no finding resulted) - not left at NotAttempted and not
	// promoted to Verified.
	found := false
	for _, c := range result.Coverage {
		if c.Category == "XSS" && c.Parameter == "q" {
			found = true
			if c.State != models.CoverageAttempted {
				t.Fatalf("expected XSS/q coverage state Attempted, got %s", c.State)
			}
		}
	}
	if !found {
		t.Fatal("expected a coverage entry for the XSS/q cell")
	}
	// NextActions is deterministic and derived purely from Coverage - it
	// must never be nil-vs-empty inconsistent with an actionable Coverage
	// snapshot when there's an Attempted-only (non-resolved) cell... but
	// Attempted itself is not actionable (only NotAttempted/Inconclusive
	// are - see pkg/planner), so just confirm the call didn't panic and
	// respects the bound.
	if len(result.NextActions) > 20 {
		t.Fatalf("expected NextActions to respect the planner's default bound, got %d", len(result.NextActions))
	}
}

func TestScan_NextActionSuggestsUntestedCategory(t *testing.T) {
	// Register two detectors but only load a payload for one, so the other
	// category is guaranteed to end the scan as NotAttempted and should
	// show up in NextActions.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	reg := detectors.NewRegistry(detectors.XSS{}, detectors.SQLi{})
	s := New(cfg, reg)
	s.payloads = map[string][]models.Payload{
		"XSS": {{ID: "t1", Category: "XSS", Value: "<xsstestmarker>"}},
		// deliberately no "SQLi" entry
	}

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sawSQLiNotAttempted := false
	for _, c := range result.Coverage {
		if c.Category == "SQLi" && c.State == models.CoverageNotAttempted {
			sawSQLiNotAttempted = true
		}
	}
	if !sawSQLiNotAttempted {
		t.Fatal("expected SQLi coverage to remain NotAttempted when no SQLi payload was loaded")
	}
	sawSQLiAction := false
	for _, a := range result.NextActions {
		if a.Category == "SQLi" {
			sawSQLiAction = true
		}
	}
	if !sawSQLiAction {
		t.Fatalf("expected a NextAction recommending the untested SQLi category, got %+v", result.NextActions)
	}
}

// --- 5. Existing behavior preserved ----------------------------------------

func TestScan_ExistingVerificationAndStatsBehaviorPreserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" {
			w.Write([]byte("<html><body>" + q + "</body></html>"))
			return
		}
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	}))
	defer srv.Close()

	cfg := Config{Workers: 4, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	result, err := s.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SchemaVersion != "arfa.scan/v1" {
		t.Fatalf("expected schema_version to be preserved, got %q", result.SchemaVersion)
	}
	if result.Stats.Requests == 0 {
		t.Fatal("expected Stats.Requests to be tracked as before")
	}
	if len(result.Findings) != 1 || result.Findings[0].VerificationStatus != "CONFIRMED" {
		t.Fatalf("expected the pre-existing verification pipeline to still confirm a genuine finding, got %+v", result.Findings)
	}
}
