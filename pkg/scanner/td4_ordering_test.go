package scanner

import (
	"context"
	"testing"
	"time"

	"arfa/pkg/models"
)

// TestScan_JobOrderIsStableAcrossRepeatedRuns is the scanner-level
// counterpart to the pkg/crawler TD #4 tests: walkJobs/streamJobs already
// iterate endpoints, detectors, payloads, parameters and encodings via
// fixed slices (never maps), so job order is deterministic *given* a
// deterministic endpoint set. This test pins that guarantee end-to-end
// with a single worker (so probe order exactly reflects job emission
// order, with no concurrency-induced interleaving) across many repeated
// Scan() calls against the same fixed multi-endpoint, multi-parameter
// input - guarding against any future regression that reintroduces
// map-derived ordering anywhere in the scheduling path.
func TestScan_JobOrderIsStableAcrossRepeatedRuns(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}

	eps := []models.Endpoint{
		{URL: "http://fake.invalid/alpha", Method: "GET", Parameters: []string{"z", "m", "a"}},
		{URL: "http://fake.invalid/beta", Method: "GET", Parameters: []string{"y", "b"}},
		{URL: "http://fake.invalid/submit", Method: "POST", FormParameters: []string{"x", "w"}},
	}

	var firstOrder []string
	const runs = 10
	for i := 0; i < runs; i++ {
		s := newTestScanner(t, cfg)
		fc := fakeCrawler{eps: eps, pages: len(eps)}
		ft := &fakeTransport{body: "<html><body>no reflection here</body></html>", status: 200}
		s.crawl = fc
		s.http = ft

		if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
			t.Fatalf("run %d: unexpected error: %v", i, err)
		}

		order := make([]string, 0, len(ft.requests))
		for _, r := range ft.requests {
			key := r.Method + " " + r.URL
			if r.Method == "POST" {
				for k := range r.FormParams {
					key += " form:" + k
				}
			} else {
				for k := range r.QueryParams {
					key += " query:" + k
				}
			}
			order = append(order, key)
		}

		if i == 0 {
			firstOrder = order
			if len(firstOrder) == 0 {
				t.Fatal("test precondition failed: expected at least one probe request")
			}
			continue
		}
		if len(order) != len(firstOrder) {
			t.Fatalf("run %d: probe count changed across runs: got %d, want %d", i, len(order), len(firstOrder))
		}
		for j := range order {
			if order[j] != firstOrder[j] {
				t.Fatalf("run %d: probe order differs at index %d: got %q, want %q\nfull got=%v\nfull want=%v",
					i, j, order[j], firstOrder[j], order, firstOrder)
			}
		}
	}
}
