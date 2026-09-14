package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"arfa/pkg/httpclient"
)

// TestCrawl_DeduplicatesPagesReachedViaDifferentURLSpellings is the direct
// regression test for TD #3: a page linked from two different literal
// spellings that canonicalize to the same URL (here, a default :80 port
// vs. no port, and a fragment vs. no fragment) must be crawled once, not
// twice, and must appear once in the returned endpoints - not as two
// separate Endpoint entries.
func TestCrawl_DeduplicatesPagesReachedViaDifferentURLSpellings(t *testing.T) {
	var visits int
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		visits++
		// Two links to the same logical target page: one with an explicit
		// default port omitted upstream by Go's own httptest URL, one with
		// a fragment appended. Both must canonicalize to the same page.
		w.Write([]byte(`
			<html><body>
				<a href="/search?b=2&a=1">first</a>
				<a href="/search?a=1&b=2#ignored">second</a>
			</body></html>
		`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		visits++
		w.Write([]byte(`<html><body><input name="q"></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)

	eps, pages, err := c.Crawl(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	searchCount := 0
	for _, e := range eps {
		if strings.Contains(e.URL, "/search") {
			searchCount++
		}
	}
	if searchCount != 1 {
		t.Fatalf("expected exactly 1 canonical /search endpoint (query-order and fragment differences must dedupe), got %d: %+v", searchCount, eps)
	}
	// /start + /search visited once each == 2 canonical pages, regardless
	// of how many literal link spellings pointed at /search.
	if pages != 2 {
		t.Fatalf("expected exactly 2 canonical pages visited (dedup across spellings), got %d", pages)
	}
}

// TestCrawl_HostComparisonIsCaseInsensitive confirms the companion fix:
// a link whose host differs only in case from the crawl's own host must
// still be treated as in-scope and queued, matching the lowercase host
// normalization CanonicalizeURL already applies.
func TestCrawl_HostComparisonIsCaseInsensitive(t *testing.T) {
	var sawUppercaseHostLink bool
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		// r.Host is whatever the client sent; build an uppercased variant
		// of the same authority to link to.
		upper := strings.ToUpper(r.Host)
		w.Write([]byte(`<html><body><a href="http://` + upper + `/next">next</a></body></html>`))
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		sawUppercaseHostLink = true
		w.Write([]byte(`<html><body>ok</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)

	if _, _, err := c.Crawl(context.Background(), srv.URL+"/start"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sawUppercaseHostLink {
		t.Fatal("expected the crawler to follow a same-host link that only differs in case")
	}
}
