package scanner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"arfa/pkg/models"
)

// --- Required test 1: known-noise parameter -> filtered --------------------

func TestFilterNoiseParameters_KnownNoiseIsFiltered(t *testing.T) {
	got := filterNoiseParameters([]string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "cache_bust", "_t"})
	if len(got) != 0 {
		t.Fatalf("expected every known-noise parameter to be filtered, got %v", got)
	}
}

// --- Required test 2: unknown parameter -> preserved ------------------------

func TestFilterNoiseParameters_UnknownParameterPreserved(t *testing.T) {
	in := []string{"id", "search_query", "redirect_url"}
	got := filterNoiseParameters(in)
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("expected unknown parameters to be preserved unchanged, got %v, want %v", got, in)
	}
}

// --- Required test 3: timestamp-looking parameter not in the list -> preserved --

func TestFilterNoiseParameters_TimestampLikeButNotListedPreserved(t *testing.T) {
	// "_t" is explicitly listed and must be filtered; "timestamp" and "ts"
	// merely *look* time-related but are not on the explicit list, so they
	// must be preserved - filtering must never infer noise from shape.
	got := filterNoiseParameters([]string{"timestamp", "ts", "_t"})
	want := []string{"timestamp", "ts"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected only the explicitly-listed '_t' to be filtered, got %v, want %v", got, want)
	}
}

// --- Required test 4: numeric parameter -> preserved -------------------------

func TestFilterNoiseParameters_NumericParameterPreserved(t *testing.T) {
	in := []string{"12345", "0"}
	got := filterNoiseParameters(in)
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("expected numeric-looking parameter names to be preserved (no shape-based inference), got %v, want %v", got, in)
	}
}

// --- Required test 5: same input -> same output (determinism) ---------------

func TestFilterNoiseParameters_Deterministic(t *testing.T) {
	in := []string{"utm_source", "id", "cache_bust", "q"}
	first := filterNoiseParameters(in)
	second := filterNoiseParameters(in)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected filtering the same input twice to yield identical results, got %v and %v", first, second)
	}
}

// Order preservation is implied by the spec's conservative/deterministic
// requirements and is asserted directly here since job/coverage ordering
// (TD #4) depends on it.
func TestFilterNoiseParameters_PreservesOrderOfSurvivors(t *testing.T) {
	got := filterNoiseParameters([]string{"z", "utm_source", "a", "cache_bust", "m"})
	want := []string{"z", "a", "m"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected survivors to keep their original relative order, got %v, want %v", got, want)
	}
}

// --- Required test 6: no regression to TD #2 / TD #4 behavior ---------------

// TestScan_KnownNoiseGETParameterIsFilteredUnknownIsScanned is the
// scanner-level regression test: a GET endpoint whose crawler-discovered
// Parameters mix a known-noise name with a real one must only ever probe
// the real one - the noise parameter must never reach a job, and the
// unaffected (TD #2/TD #4) GET query-parameter transport must still work.
func TestScan_KnownNoiseGETParameterIsFilteredUnknownIsScanned(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/page", Method: "GET", Parameters: []string{"utm_source", "id"}},
	}, pages: 1}
	ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range ft.requests {
		if _, filtered := r.QueryParams["utm_source"]; filtered {
			t.Fatalf("expected the known-noise parameter 'utm_source' to never be probed, got request %+v", r)
		}
	}
	sawID := false
	for _, r := range ft.requests {
		if _, ok := r.QueryParams["id"]; ok {
			sawID = true
		}
	}
	if !sawID {
		t.Fatal("expected the unaffected parameter 'id' to still be probed")
	}
}

// TestScan_KnownNoisePOSTFormParameterIsFiltered confirms filtering also
// applies to POST FormParameters (TD #2's transport) without breaking the
// existing form-urlencoded body transport for the surviving field.
func TestScan_KnownNoisePOSTFormParameterIsFiltered(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/submit", Method: "POST", FormParameters: []string{"cache_bust", "email"}},
	}, pages: 1}
	ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range ft.requests {
		if _, filtered := r.FormParams["cache_bust"]; filtered {
			t.Fatalf("expected the known-noise form parameter 'cache_bust' to never be probed, got request %+v", r)
		}
	}
	sawEmail := false
	for _, r := range ft.requests {
		if _, ok := r.FormParams["email"]; ok {
			sawEmail = true
		}
	}
	if !sawEmail {
		t.Fatal("expected the unaffected form parameter 'email' to still be probed")
	}
}

// TestScan_NoiseFilteringDoesNotAffectGETFallbackGuessList confirms TD #5
// does not touch effectiveParams' separate fallback guess list: a GET
// endpoint with zero discovered parameters still falls back to the
// unchanged 5-entry guess list (q, id, search, page, url), exactly as
// before TD #5.
func TestScan_NoiseFilteringDoesNotAffectGETFallbackGuessList(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	fc := fakeCrawler{eps: []models.Endpoint{
		{URL: "http://fake.invalid/static", Method: "GET"}, // no discovered Parameters
	}, pages: 1}
	ft := &fakeTransport{body: "<html><body>static</body></html>", status: 200}
	s.crawl = fc
	s.http = ft

	if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{"q": true, "id": true, "search": true, "page": true, "url": true}
	seen := map[string]bool{}
	for _, r := range ft.requests {
		for k := range r.QueryParams {
			seen[k] = true
		}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("expected the unchanged 5-entry GET fallback guess list to be probed, got %v, want %v", seen, want)
	}
}
