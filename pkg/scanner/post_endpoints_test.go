package scanner

import (
	"context"
	"testing"
	"time"

	"arfa/pkg/models"
)

// TestScan_GETJobUsesQueryParamsPOSTJobUsesFormParams covers required test
// item 7: a GET endpoint's job places its selected parameter in
// httpclient.Request.QueryParams, while a POST endpoint's job places its
// selected parameter in FormParams - never the other, and never both at
// once for the same job.
func TestScan_GETJobUsesQueryParamsPOSTJobUsesFormParams(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/get-page", Method: "GET", Parameters: []string{"q"}},
		{URL: "http://fake.invalid/post-page", Method: "POST", FormParameters: []string{"x"}},
	}, pages: 2}
	ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sawGETQuery, sawPOSTForm bool
	for _, r := range ft.requests {
		switch r.Method {
		case "GET":
			if len(r.QueryParams) != 1 || r.QueryParams.Get("q") == "" {
				t.Fatalf("expected the GET job to place its parameter in QueryParams[q], got %+v", r)
			}
			if len(r.FormParams) != 0 {
				t.Fatalf("expected the GET job to carry no FormParams, got %v", r.FormParams)
			}
			sawGETQuery = true
		case "POST":
			if len(r.FormParams) != 1 || r.FormParams.Get("x") == "" {
				t.Fatalf("expected the POST job to place its parameter in FormParams[x], got %+v", r)
			}
			if len(r.QueryParams) != 0 {
				t.Fatalf("expected the POST job to carry no QueryParams, got %v", r.QueryParams)
			}
			sawPOSTForm = true
		default:
			t.Fatalf("unexpected request method %q", r.Method)
		}
	}
	if !sawGETQuery {
		t.Fatal("expected at least one GET request placing its param in QueryParams")
	}
	if !sawPOSTForm {
		t.Fatal("expected at least one POST request placing its param in FormParams")
	}
}

// TestScan_POSTSendsOnlyTheMutatedField covers required test item 8: a
// POST endpoint with multiple form fields must send exactly one field per
// probe (the currently-selected/mutated one) - never the endpoint's other
// fields, and never an empty-value placeholder for them.
func TestScan_POSTSendsOnlyTheMutatedField(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/submit", Method: "POST", FormParameters: []string{"a", "b"}},
	}, pages: 1}
	ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ft.requests) == 0 {
		t.Fatal("expected at least one request to have been sent")
	}
	for _, r := range ft.requests {
		if r.Method != "POST" {
			t.Fatalf("expected every probe against a POST endpoint to use POST, got %q", r.Method)
		}
		if len(r.FormParams) != 1 {
			t.Fatalf("expected exactly one mutated field per POST probe (never the endpoint's other fields), got %v", r.FormParams)
		}
		for k := range r.FormParams {
			if k != "a" && k != "b" {
				t.Fatalf("expected the mutated field to be one of the endpoint's own declared fields (a or b), got %q", k)
			}
		}
	}
}

// TestScan_POSTJobCountUsesFormParametersNotGETFallback confirms
// effectiveParams()'s GET-oriented fallback guess list (q, id, search,
// page, url) is never consulted for a POST endpoint: a POST endpoint with
// zero discovered FormParameters schedules zero jobs, rather than falling
// back to the 5-entry GET guess list.
func TestScan_POSTJobCountUsesFormParametersNotGETFallback(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/submit", Method: "POST"}, // FormParameters intentionally empty
	}, pages: 1}
	ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stats.JobsPlanned != 0 {
		t.Fatalf("expected 0 jobs planned for a POST endpoint with no FormParameters (no GET fallback), got %d", result.Stats.JobsPlanned)
	}
	if len(ft.requests) != 0 {
		t.Fatalf("expected zero requests for a POST endpoint with nothing to mutate, got %d", len(ft.requests))
	}
}

// TestScan_POSTCoverageSeededFromFormParameters confirms coverage seeding
// (item 7) is method-aware: a POST endpoint's coverage cells are seeded
// from FormParameters, not from effectiveParams()'s GET fallback list.
func TestScan_POSTCoverageSeededFromFormParameters(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/submit", Method: "POST", FormParameters: []string{"x"}},
	}, pages: 1}
	ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sawXSSCoverageForX := false
	for _, c := range result.Coverage {
		if c.Category == "XSS" {
			if c.Parameter == "x" {
				sawXSSCoverageForX = true
			}
			// None of the GET-fallback names (q, id, search, page, url)
			// should ever appear for this POST-only endpoint.
			for _, fallback := range []string{"q", "id", "search", "page", "url"} {
				if c.Parameter == fallback {
					t.Fatalf("did not expect GET-fallback parameter %q in coverage for a POST endpoint, got entry: %+v", fallback, c)
				}
			}
		}
	}
	if !sawXSSCoverageForX {
		t.Fatalf("expected an XSS coverage entry for the POST endpoint's own field 'x', got coverage: %+v", result.Coverage)
	}
}

// TestEffectiveParams_UnchangedByTD2 locks in that effectiveParams() itself
// (the GET fallback owned by TD #5) is untouched by this change: it still
// returns the endpoint's own Parameters when non-empty, and the same
// 5-entry guess list otherwise, regardless of Method.
func TestEffectiveParams_UnchangedByTD2(t *testing.T) {
	got := effectiveParams(models.Endpoint{Method: "GET", Parameters: []string{"a", "b"}})
	want := []string{"a", "b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected effectiveParams to return the endpoint's own Parameters unchanged, got %v", got)
	}

	got = effectiveParams(models.Endpoint{Method: "GET"})
	want = []string{"q", "id", "search", "page", "url"}
	if len(got) != len(want) {
		t.Fatalf("expected the unchanged 5-entry GET fallback list, got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected the unchanged 5-entry GET fallback list %v, got %v", want, got)
		}
	}
}
