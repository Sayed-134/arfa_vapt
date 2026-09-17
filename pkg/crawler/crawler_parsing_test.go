package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"arfa/pkg/httpclient"
	"arfa/pkg/models"
)

// serveHTML starts an httptest server that returns the given HTML body for
// every request path, and returns the server plus a helper to run a crawl
// against it and collect the resulting endpoints.
func serveHTML(t *testing.T, body string) (*httptest.Server, func(t *testing.T) ([]string, int)) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	run := func(t *testing.T) ([]string, int) {
		t.Helper()
		hc := httpclient.New(2 * time.Second)
		c := New(hc, 10)
		eps, _, err := c.Crawl(context.Background(), srv.URL+"/")
		if err != nil {
			t.Fatalf("Crawl error: %v", err)
		}
		// Flatten all parameter names discovered across endpoints, sorted
		// for stable comparison.
		var names []string
		for _, e := range eps {
			names = append(names, e.Parameters...)
		}
		sort.Strings(names)
		return names, len(eps)
	}
	return srv, run
}

// --- link discovery -------------------------------------------------------

// TestParsePage_LinkDiscovery_QuotedAndUnquoted asserts that link
// attributes are extracted whether quoted (single or double) or unquoted.
// The unquoted cases are the parsing-correctness improvement TD #1 adds.
func TestParsePage_LinkDiscovery_QuotedAndUnquoted(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "double-quoted href",
			body: `<a href="/one">x</a>`,
			want: []string{"/one"},
		},
		{
			name: "single-quoted href",
			body: `<a href='/one'>x</a>`,
			want: []string{"/one"},
		},
		{
			name: "unquoted href",
			body: `<a href=/one>x</a>`,
			want: []string{"/one"},
		},
		{
			name: "uppercase element and attribute",
			body: `<A HREF="/one">x</A>`,
			want: []string{"/one"},
		},
		{
			name: "whitespace around equals",
			body: `<a href = "/one">x</a>`,
			want: []string{"/one"},
		},
		{
			name: "src on script",
			body: `<script src="/app.js"></script>`,
			want: []string{"/app.js"},
		},
		{
			name: "action on form is link discovery only",
			body: `<form action="/submit" method="post"></form>`,
			want: []string{"/submit"},
		},
		{
			name: "img src",
			body: `<img src="/logo.png" alt="logo">`,
			want: []string{"/logo.png"},
		},
		{
			name: "multiple link attributes on same element",
			body: `<a href="/a" data-src="/b">x</a>`,
			want: []string{"/a"}, // only href is a link attribute; data-src is not
		},
		{
			name: "reordered attributes with extra in between",
			body: `<a class="btn" target="_blank" href="/path">x</a>`,
			want: []string{"/path"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			links, _, _ := parsePage(tc.body)
			sort.Strings(links)
			sort.Strings(tc.want)
			if !equalStrings(links, tc.want) {
				t.Fatalf("parsePage(%q) links = %v; want %v", tc.body, links, tc.want)
			}
		})
	}
}

// TestParsePage_FragmentPreservedInParsedValue confirms the parser does not
// strip fragments - canonicalization is responsible for that (see
// canonicalOrOriginal). The raw parsed value must keep "#section".
func TestParsePage_FragmentPreservedInParsedValue(t *testing.T) {
	links, _, _ := parsePage(`<a href="/path#section">x</a>`)
	if len(links) != 1 || links[0] != "/path#section" {
		t.Fatalf("expected raw parsed href to preserve fragment, got %v", links)
	}
}

// --- parameter name discovery --------------------------------------------

// TestParsePage_NameDiscovery asserts name attributes are extracted from
// input, textarea, and select only, and only from those elements.
func TestParsePage_NameDiscovery(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "input name double-quoted",
			body: `<input name="q">`,
			want: []string{"q"},
		},
		{
			name: "input name single-quoted",
			body: `<input name='q'>`,
			want: []string{"q"},
		},
		{
			name: "input name unquoted",
			body: `<input name=q>`,
			want: []string{"q"},
		},
		{
			name: "textarea name",
			body: `<textarea name="body"></textarea>`,
			want: []string{"body"},
		},
		{
			name: "select name",
			body: `<select name="color"></select>`,
			want: []string{"color"},
		},
		{
			name: "self-closing input",
			body: `<input name="q" />`,
			want: []string{"q"},
		},
		{
			name: "uppercase NAME attribute",
			body: `<input NAME="q">`,
			want: []string{"q"},
		},
		{
			name: "multiple inputs",
			body: `<input name="a"><input name="b"><input name="c">`,
			want: []string{"a", "b", "c"},
		},
		{
			name: "name on non-target element is ignored",
			body: `<div name="ignored"></div><input name="kept">`,
			want: []string{"kept"},
		},
		{
			name: "name inside text content is ignored",
			body: `<p>The word name="x" is not an attribute.</p><input name="kept">`,
			want: []string{"kept"},
		},
		{
			name: "input without name attribute",
			body: `<input type="text" value="x">`,
			want: nil,
		},
		{
			name: "name inside a comment is ignored",
			body: `<input name="kept"><!-- <input name="comment"> -->`,
			want: []string{"kept"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, names, _ := parsePage(tc.body)
			sort.Strings(names)
			sort.Strings(tc.want)
			if !equalStrings(names, tc.want) {
				t.Fatalf("parsePage(%q) names = %v; want %v", tc.body, names, tc.want)
			}
		})
	}
}

// --- malformed / tricky HTML ---------------------------------------------

// TestParsePage_MalformedButParseable confirms that the tokenizer recovers
// from common malformations without losing the extractable attributes.
//
// Note on the "unterminated tag" case: an HTML5-compliant tokenizer treats
// `<input name="q"` (no closing `>`) as an error token, not as a start
// tag - the element is never actually opened. This is intentionally NOT
// extracted. The previous flat-regex happened to match the substring
// `name="q"` inside a syntactically invalid tag; that was a false
// positive. TD #1's parser is expected to be stricter here, and the
// "unterminated tag is not extracted" case documents that expectation.
func TestParsePage_MalformedButParseable(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantLinks []string
		wantNames []string
	}{
		{
			name:      "unclosed anchor",
			body:      `<a href="/x">unclosed`,
			wantLinks: []string{"/x"},
		},
		{
			// An unterminated tag has no `>`, so it is not a start tag at
			// all under HTML5 tokenization. Not extracting it is correct.
			name:      "unterminated tag is not extracted",
			body:      `<input name="q"`,
			wantNames: nil,
		},
		{
			name:      "input with attributes and closure",
			body:      `<input name="q" type="text">`,
			wantNames: []string{"q"},
		},
		{
			name:      "input followed by non-html content",
			body:      `<input name="q"><garbage!@#>`,
			wantNames: []string{"q"},
		},
		{
			name:      "stray text before element",
			body:      `junk junk <a href="/x">link</a>`,
			wantLinks: []string{"/x"},
		},
		{
			name:      "nested unclosed tags",
			body:      `<div><a href="/x"><span></div>`,
			wantLinks: []string{"/x"},
		},
		{
			name:      "attribute value with entity",
			body:      `<a href="/search?q=a&amp;b=c">x</a>`,
			wantLinks: []string{"/search?q=a&b=c"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			links, names, _ := parsePage(tc.body)
			sort.Strings(links)
			sort.Strings(tc.wantLinks)
			sort.Strings(names)
			sort.Strings(tc.wantNames)
			if !equalStrings(links, tc.wantLinks) {
				t.Fatalf("links = %v; want %v", links, tc.wantLinks)
			}
			if !equalStrings(names, tc.wantNames) {
				t.Fatalf("names = %v; want %v", names, tc.wantNames)
			}
		})
	}
}

// --- behavioral contract preserved end-to-end ----------------------------

// TestCrawl_UnquotedHrefIsFollowed is an end-to-end check: a page whose
// only link is unquoted must still be followed by Crawl (the old regex
// would have missed it).
func TestCrawl_UnquotedHrefIsFollowed(t *testing.T) {
	var reached bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			reached = true
		}
		w.Write([]byte(`<html><body><a href=/next>go</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)
	if _, _, err := c.Crawl(context.Background(), srv.URL+"/"); err != nil {
		t.Fatalf("Crawl error: %v", err)
	}
	if !reached {
		t.Fatal("expected crawler to follow unquoted href=/next")
	}
}

// TestCrawl_FormMethodDeterminesEndpointMethod replaces the old
// TestCrawl_MethodIsAlwaysGET. That test guarded TD #1's explicit non-goal
// ("the crawler must never emit a non-GET endpoint") and said so in its own
// doc comment: "This is the boundary between TD #1 (parsing) and TD #2
// (POST/form support)." TD #2 is exactly the work that moves that
// boundary, so the old blanket assertion is no longer valid by design -
// this test replaces it with the new contract:
//   - a form explicitly declaring method="get" (or omitting method)
//     produces a GET endpoint at its action URL, params in Parameters;
//   - a form explicitly declaring method="post" produces a POST endpoint
//     at its action URL, fields in FormParameters, never in Parameters;
//   - the page's own GET endpoint (page-level parameter aggregation, see
//     parsePage) remains GET, unaffected by any form on the page;
//   - therefore "every discovered endpoint is GET" is no longer true, and
//     this test asserts the opposite - at least one non-GET endpoint
//     exists - as the direct replacement for the old assertion.
func TestCrawl_FormMethodDeterminesEndpointMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form action="/search" method="get"><input name="q"></form>
			<form action="/submit" method="post"><input name="x"></form>
		</body></html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>no further links or forms here</body></html>`))
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>no further links or forms here</body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)
	eps, _, err := c.Crawl(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	byKey := map[string]models.Endpoint{}
	for _, e := range eps {
		byKey[e.URL+" "+e.Method] = e
	}

	// Old TD #1 expectation no longer holds: TD #2 intentionally
	// introduces POST endpoints from forms declaring method="post".
	sawNonGET := false
	for _, e := range eps {
		if e.Method != "GET" {
			sawNonGET = true
		}
	}
	if !sawNonGET {
		t.Fatalf("expected at least one non-GET endpoint from the method=\"post\" form - TD #2 changes the old TD #1 GET-only boundary; got endpoints: %+v", eps)
	}

	// The method="get" form resolves to a GET endpoint at its action URL.
	searchKey := canonicalOrOriginal(srv.URL+"/search") + " GET"
	getEP, ok := byKey[searchKey]
	if !ok {
		t.Fatalf("expected a GET endpoint at key %q from the method=\"get\" form, got endpoints: %+v", searchKey, eps)
	}
	if len(getEP.Parameters) != 1 || getEP.Parameters[0] != "q" {
		t.Fatalf("expected the method=\"get\" form's endpoint to carry Parameters=[\"q\"], got %+v", getEP.Parameters)
	}
	if len(getEP.FormParameters) != 0 {
		t.Fatalf("expected the method=\"get\" form's endpoint to carry no FormParameters, got %+v", getEP.FormParameters)
	}

	// The method="post" form resolves to a POST endpoint at its action
	// URL, carrying the field in FormParameters - never in Parameters.
	submitKey := canonicalOrOriginal(srv.URL+"/submit") + " POST"
	postEP, ok := byKey[submitKey]
	if !ok {
		t.Fatalf("expected a POST endpoint at key %q from the method=\"post\" form, got endpoints: %+v", submitKey, eps)
	}
	if len(postEP.FormParameters) != 1 || postEP.FormParameters[0] != "x" {
		t.Fatalf("expected the method=\"post\" form's endpoint to carry FormParameters=[\"x\"], got %+v", postEP.FormParameters)
	}
	if len(postEP.Parameters) != 0 {
		t.Fatalf("expected the method=\"post\" form's endpoint to carry no query Parameters, got %+v", postEP.Parameters)
	}

	// The page's own GET endpoint remains present and GET - TD #2 only
	// ever adds new (form-derived) endpoints, it never changes an
	// existing GET endpoint's method.
	rootKey := canonicalOrOriginal(srv.URL+"/") + " GET"
	if _, ok := byKey[rootKey]; !ok {
		t.Fatalf("expected the root page's own GET endpoint at key %q to remain present, got endpoints: %+v", rootKey, eps)
	}
}

// TestCrawl_FormActionIsLinkNotParameter confirms that a form's action is
// still treated as a link (its URL becomes a queued page) on top of - not
// instead of - being followed as a form-derived GET endpoint: the input's
// name is a parameter on both the root page (page-level aggregation,
// unchanged since before TD #2) and, via TD #2, on the /submit GET
// endpoint the method="get" form itself produces. This test predates
// TD #2 and originally asserted only the "action is a link" half; its
// assertions still hold unchanged post-TD #2 (both endpoints legitimately
// carry the "q" parameter), so no assertion here needed to change.
func TestCrawl_FormActionIsLinkNotParameter(t *testing.T) {
	var submitVisited bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/submit" {
			submitVisited = true
		}
		w.Write([]byte(`<html><body>
			<form action="/submit" method="get"><input name="q"></form>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)
	eps, _, err := c.Crawl(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}
	if !submitVisited {
		t.Fatal("expected /submit (from form action) to be crawled as a link")
	}

	// The form input's name should be a parameter on the root page.
	var rootParams []string
	for _, e := range eps {
		if strings.HasSuffix(e.URL, "/") {
			rootParams = e.Parameters
		}
	}
	found := false
	for _, p := range rootParams {
		if p == "q" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected input name 'q' in root page parameters, got %v", rootParams)
	}
}

// --- helpers --------------------------------------------------------------

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
