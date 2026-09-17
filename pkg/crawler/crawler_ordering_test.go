package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"arfa/pkg/httpclient"
	"arfa/pkg/models"
)

// TestCrawl_EndpointOrderIsStableAcrossRepeatedRuns is the direct
// regression test for TD #4: Crawl()'s returned Endpoints previously came
// from ranging over a map keyed by canonical URL + method (TD #2 endpoint
// identity), and Go randomizes map iteration order on every range - not
// just once per process. A target with several GET endpoints and several
// POST form endpoints, crawled many times in a row, must return the exact
// same Endpoint order (by URL, then Method) every single time.
func TestCrawl_EndpointOrderIsStableAcrossRepeatedRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body>
				<a href="/zebra?z=1">zebra</a>
				<a href="/alpha?a=1">alpha</a>
				<a href="/mid?m=1">mid</a>
				<form method="post" action="/submit-b"><input name="x"></form>
				<form method="post" action="/submit-a"><input name="y"></form>
			</body></html>`))
		default:
			w.Write([]byte(`<html><body>leaf page</body></html>`))
		}
	}))
	defer srv.Close()

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 20)

	var first []models.Endpoint
	const runs = 25
	for i := 0; i < runs; i++ {
		eps, _, err := c.Crawl(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("run %d: unexpected error: %v", i, err)
		}
		if i == 0 {
			first = eps
			if len(first) < 2 {
				t.Fatalf("test precondition failed: expected at least 2 endpoints to make ordering meaningful, got %d", len(first))
			}
			continue
		}
		if len(eps) != len(first) {
			t.Fatalf("run %d: endpoint count changed across runs: got %d, want %d", i, len(eps), len(first))
		}
		for j := range eps {
			if eps[j].URL != first[j].URL || eps[j].Method != first[j].Method {
				t.Fatalf("run %d: endpoint order differs at index %d: got (%s %s), want (%s %s)\nfull got=%+v\nfull want=%+v",
					i, j, eps[j].Method, eps[j].URL, first[j].Method, first[j].URL, eps, first)
			}
		}
	}
}

// TestCrawl_EndpointOrderIsSortedByURLThenMethod pins the actual ordering
// contract (not just "stable, whatever it is"): Endpoints come back sorted
// by URL ascending, then Method ascending for ties on the same URL.
func TestCrawl_EndpointOrderIsSortedByURLThenMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>
			<form method="get" action="/same?q=1"><input name="q"></form>
			<form method="post" action="/same"><input name="q"></form>
		</body></html>`))
	}))
	defer srv.Close()

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 20)

	eps, _, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 1; i < len(eps); i++ {
		prev, cur := eps[i-1], eps[i]
		if prev.URL > cur.URL || (prev.URL == cur.URL && prev.Method > cur.Method) {
			t.Fatalf("endpoints not sorted by (URL, Method): index %d=(%s %s) comes after index %d=(%s %s)",
				i, cur.Method, cur.URL, i-1, prev.Method, prev.URL)
		}
	}
}

// TestCrawl_GETEndpointParameterOrderIsStableAcrossRepeatedRuns covers the
// second TD #4 source of non-determinism: a page-level GET endpoint's own
// query-string parameter names were previously collected by ranging over
// url.Values (also a map), independent of the Endpoint-slice ordering
// fixed above. A URL with several query parameters must yield the exact
// same Endpoint.Parameters order every run.
func TestCrawl_GETEndpointParameterOrderIsStableAcrossRepeatedRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>static, no links, no forms</body></html>`))
	}))
	defer srv.Close()

	target := srv.URL + "/page?zulu=1&mike=2&alpha=3&kilo=4&bravo=5"
	hc := httpclient.New(2 * time.Second)
	c := New(hc, 20)

	var first []string
	const runs = 25
	for i := 0; i < runs; i++ {
		eps, _, err := c.Crawl(context.Background(), target)
		if err != nil {
			t.Fatalf("run %d: unexpected error: %v", i, err)
		}
		if len(eps) != 1 {
			t.Fatalf("run %d: expected exactly 1 endpoint, got %d: %+v", i, len(eps), eps)
		}
		params := eps[0].Parameters
		if i == 0 {
			first = params
			wantSet := map[string]bool{"zulu": true, "mike": true, "alpha": true, "kilo": true, "bravo": true}
			if len(first) != len(wantSet) {
				t.Fatalf("test precondition failed: expected %d query parameters, got %v", len(wantSet), first)
			}
			for _, p := range first {
				if !wantSet[p] {
					t.Fatalf("unexpected parameter %q discovered", p)
				}
			}
			continue
		}
		if !equalStrings(params, first) {
			t.Fatalf("run %d: parameter order differs: got %v, want %v", i, params, first)
		}
	}
	// Pin the actual contract: sorted ascending.
	want := []string{"alpha", "bravo", "kilo", "mike", "zulu"}
	if !equalStrings(first, want) {
		t.Fatalf("expected query parameters sorted ascending %v, got %v", want, first)
	}
}
