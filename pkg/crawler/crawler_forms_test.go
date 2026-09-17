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

// --- parsePage-level form field extraction ---------------------------------

// TestParsePage_FormFieldExtraction_InputTextareaSelect covers required
// test item 3: input, textarea, and select elements inside a <form> all
// contribute their name attribute to that form's fields, in document
// order, alongside the pre-existing flat names list.
func TestParsePage_FormFieldExtraction_InputTextareaSelect(t *testing.T) {
	body := `<html><body>
		<form method="post" action="/x">
			<input name="a" value="1">
			<textarea name="b">hello</textarea>
			<select name="c"><option value="1">one</option></select>
			<input type="hidden" name="d">
		</form>
	</body></html>`

	_, names, forms := parsePage(body)

	if len(forms) != 1 {
		t.Fatalf("expected exactly 1 form, got %d: %+v", len(forms), forms)
	}
	f := forms[0]
	if f.method != "POST" {
		t.Fatalf("expected form method POST, got %q", f.method)
	}
	if f.action != "/x" {
		t.Fatalf("expected form action /x, got %q", f.action)
	}
	wantFields := []string{"a", "b", "c", "d"}
	if !equalStrings(f.fields, wantFields) {
		t.Fatalf("expected form fields %v, got %v", wantFields, f.fields)
	}
	// The pre-existing flat names list is unaffected by form scoping.
	if !equalStrings(names, wantFields) {
		t.Fatalf("expected flat names %v, got %v", wantFields, names)
	}
}

// TestParsePage_FormFieldsExcludeFieldsOutsideForm confirms a field outside
// any <form> is never attributed to a form's fields, even though it still
// appears in the page-level flat names list.
func TestParsePage_FormFieldsExcludeFieldsOutsideForm(t *testing.T) {
	body := `<html><body>
		<input name="outside">
		<form action="/x"><input name="inside"></form>
	</body></html>`

	_, names, forms := parsePage(body)

	if len(forms) != 1 {
		t.Fatalf("expected exactly 1 form, got %d", len(forms))
	}
	if !equalStrings(forms[0].fields, []string{"inside"}) {
		t.Fatalf("expected form fields [inside], got %v", forms[0].fields)
	}
	if !equalStrings(names, []string{"outside", "inside"}) {
		t.Fatalf("expected flat names [outside inside], got %v", names)
	}
}

// TestParsePage_MultipleFormsScopedIndependently confirms fields from two
// separate forms on the same page never leak into each other.
func TestParsePage_MultipleFormsScopedIndependently(t *testing.T) {
	body := `<html><body>
		<form action="/a"><input name="x"></form>
		<form action="/b"><input name="y"></form>
	</body></html>`

	_, _, forms := parsePage(body)

	if len(forms) != 2 {
		t.Fatalf("expected exactly 2 forms, got %d: %+v", len(forms), forms)
	}
	if !equalStrings(forms[0].fields, []string{"x"}) {
		t.Fatalf("expected form[0] fields [x], got %v", forms[0].fields)
	}
	if !equalStrings(forms[1].fields, []string{"y"}) {
		t.Fatalf("expected form[1] fields [y], got %v", forms[1].fields)
	}
}

// TestParsePage_FormMethodMissingOrInvalidDefaultsToGET covers required
// test item 4: a form with no method attribute, an empty method
// attribute, or an unrecognized method value (e.g. "put") all resolve to
// GET - only an exact case-insensitive "post" resolves to POST.
func TestParsePage_FormMethodMissingOrInvalidDefaultsToGET(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"no method attribute", `<form action="/x"><input name="a"></form>`},
		{"empty method attribute", `<form method="" action="/x"><input name="a"></form>`},
		{"invalid method value", `<form method="put" action="/x"><input name="a"></form>`},
		{"mixed-case get is still GET", `<form method="GeT" action="/x"><input name="a"></form>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, forms := parsePage(tc.body)
			if len(forms) != 1 {
				t.Fatalf("expected exactly 1 form, got %d", len(forms))
			}
			if forms[0].method != "GET" {
				t.Fatalf("expected method GET, got %q", forms[0].method)
			}
		})
	}
}

// TestParsePage_FormMethodPostIsCaseInsensitive confirms method="POST" is
// recognized regardless of case.
func TestParsePage_FormMethodPostIsCaseInsensitive(t *testing.T) {
	cases := []string{"post", "POST", "Post", "pOsT"}
	for _, m := range cases {
		body := `<form method="` + m + `" action="/x"><input name="a"></form>`
		_, _, forms := parsePage(body)
		if len(forms) != 1 || forms[0].method != "POST" {
			t.Fatalf("method=%q: expected form method POST, got forms=%+v", m, forms)
		}
	}
}

// --- Crawl-level endpoint construction --------------------------------------

// newFormMux builds an httptest server where each registered path serves
// the given body, and any other path serves a minimal fieldless, linkless
// page (so the crawl stays small and deterministic). A single handler is
// used (rather than one ServeMux registration per path) so a pages map
// that itself defines "/" doesn't collide with the catch-all fallback.
func newFormMux(t *testing.T, pages map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Path]
		if !ok {
			body = `<html><body>dead end</body></html>`
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func crawlEndpoints(t *testing.T, srv *httptest.Server) []models.Endpoint {
	t.Helper()
	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)
	eps, _, err := c.Crawl(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}
	return eps
}

func findEndpoint(eps []models.Endpoint, url, method string) (models.Endpoint, bool) {
	for _, e := range eps {
		if e.URL == url && e.Method == method {
			return e, true
		}
	}
	return models.Endpoint{}, false
}

// TestCrawl_EmptyFormActionResolvesToCurrentPage covers required test item
// 5: a form with no action attribute (or an empty one) submits to the page
// it appears on, not to some default/blank URL.
func TestCrawl_EmptyFormActionResolvesToCurrentPage(t *testing.T) {
	srv := newFormMux(t, map[string]string{
		"/": `<html><body><form method="post"><input name="x"></form></body></html>`,
	})
	eps := crawlEndpoints(t, srv)

	want := canonicalOrOriginal(srv.URL + "/")
	ep, ok := findEndpoint(eps, want, "POST")
	if !ok {
		t.Fatalf("expected a POST endpoint at the page's own URL %q for a form with no action, got endpoints: %+v", want, eps)
	}
	if !equalStrings(ep.FormParameters, []string{"x"}) {
		t.Fatalf("expected FormParameters [x], got %v", ep.FormParameters)
	}
}

// TestCrawl_SameURLSameMethodMergesAndDedupsParameters covers required
// test item 6: two forms (on different pages) that POST to the same
// action URL contribute a single merged, deduplicated POST endpoint - not
// two separate entries and not a last-write-wins overwrite.
func TestCrawl_SameURLSameMethodMergesAndDedupsParameters(t *testing.T) {
	srv := newFormMux(t, map[string]string{
		"/": `<html><body>
			<a href="/page2">next</a>
			<form method="post" action="/submit"><input name="a"><input name="b"></form>
		</body></html>`,
		"/page2": `<html><body>
			<form method="post" action="/submit"><input name="b"><input name="c"></form>
		</body></html>`,
	})
	eps := crawlEndpoints(t, srv)

	want := canonicalOrOriginal(srv.URL + "/submit")
	ep, ok := findEndpoint(eps, want, "POST")
	if !ok {
		t.Fatalf("expected a single merged POST endpoint at %q, got endpoints: %+v", want, eps)
	}
	// Union of {a,b} and {b,c}, deduplicated, in first-seen order.
	wantFields := []string{"a", "b", "c"}
	if !equalStrings(ep.FormParameters, wantFields) {
		t.Fatalf("expected merged/deduplicated FormParameters %v, got %v", wantFields, ep.FormParameters)
	}

	// Exactly one POST endpoint at that key - not two separate entries.
	count := 0
	for _, e := range eps {
		if e.URL == want && e.Method == "POST" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 POST endpoint at %q, found %d among: %+v", want, count, eps)
	}
}

// TestCrawl_SameURLDifferentMethodKeptSeparate covers required test item 6
// (the other half): a GET form and a POST form that both target the same
// action URL produce two distinct endpoints, identified by (URL, Method),
// never merged into one.
func TestCrawl_SameURLDifferentMethodKeptSeparate(t *testing.T) {
	srv := newFormMux(t, map[string]string{
		"/": `<html><body>
			<form method="get" action="/target"><input name="q"></form>
			<form method="post" action="/target"><input name="x"></form>
		</body></html>`,
	})
	eps := crawlEndpoints(t, srv)

	want := canonicalOrOriginal(srv.URL + "/target")
	getEP, getOK := findEndpoint(eps, want, "GET")
	postEP, postOK := findEndpoint(eps, want, "POST")
	if !getOK {
		t.Fatalf("expected a GET endpoint at %q, got endpoints: %+v", want, eps)
	}
	if !postOK {
		t.Fatalf("expected a POST endpoint at %q, got endpoints: %+v", want, eps)
	}
	if !equalStrings(getEP.Parameters, []string{"q"}) {
		t.Fatalf("expected GET endpoint Parameters [q], got %v", getEP.Parameters)
	}
	if !equalStrings(postEP.FormParameters, []string{"x"}) {
		t.Fatalf("expected POST endpoint FormParameters [x], got %v", postEP.FormParameters)
	}
	if len(getEP.FormParameters) != 0 {
		t.Fatalf("expected the GET endpoint to carry no FormParameters, got %v", getEP.FormParameters)
	}
	if len(postEP.Parameters) != 0 {
		t.Fatalf("expected the POST endpoint to carry no Parameters, got %v", postEP.Parameters)
	}
}

// TestCrawl_FieldlessFormProducesNoEndpoint confirms a <form> with no
// named input/textarea/select fields contributes no endpoint at all -
// there is nothing to mutate, so scheduling a job for it would be
// meaningless.
func TestCrawl_FieldlessFormProducesNoEndpoint(t *testing.T) {
	srv := newFormMux(t, map[string]string{
		"/": `<html><body><form method="post" action="/empty-submit"></form></body></html>`,
	})
	eps := crawlEndpoints(t, srv)

	want := canonicalOrOriginal(srv.URL + "/empty-submit")
	if _, ok := findEndpoint(eps, want, "POST"); ok {
		t.Fatalf("expected no POST endpoint at %q for a fieldless form, got endpoints: %+v", want, eps)
	}
}

// TestCrawl_RelativeFormActionResolvesAgainstPageURL confirms a relative
// action attribute is resolved against the crawled page's own URL, not the
// original crawl target.
func TestCrawl_RelativeFormActionResolvesAgainstPageURL(t *testing.T) {
	srv := newFormMux(t, map[string]string{
		"/dir/page": `<html><body><form method="post" action="sibling"><input name="x"></form></body></html>`,
	})

	hc := httpclient.New(2 * time.Second)
	c := New(hc, 10)
	// Start the crawl directly at /dir/page (rather than "/") so this test
	// stays focused on action resolution, independent of link discovery.
	eps, _, err := c.Crawl(context.Background(), srv.URL+"/dir/page")
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	want := canonicalOrOriginal(srv.URL + "/dir/sibling")
	if _, ok := findEndpoint(eps, want, "POST"); !ok {
		t.Fatalf("expected a POST endpoint at %q (relative action resolved against the page URL), got endpoints: %+v", want, eps)
	}
}
