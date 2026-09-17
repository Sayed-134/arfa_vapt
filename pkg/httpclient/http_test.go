package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// capturedRequest records everything the test server observed about one
// incoming request, so assertions can inspect method, URL, headers, and
// body together.
type capturedRequest struct {
	method      string
	url         *url.URL
	contentType string
	body        string
}

func newCaptureServer(t *testing.T) (*httptest.Server, chan capturedRequest) {
	t.Helper()
	ch := make(chan capturedRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- capturedRequest{method: r.Method, url: r.URL, contentType: r.Header.Get("Content-Type"), body: string(b)}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// TestDo_GETSendsQueryParamsNoBody covers item 1 of the required TD #2
// tests: a GET request (Request.Method == "" or "GET") encodes
// QueryParams onto the URL query string and sends no request body at all.
func TestDo_GETSendsQueryParamsNoBody(t *testing.T) {
	srv, ch := newCaptureServer(t)
	c := New(2 * time.Second)

	body, status, _, _, err := c.Do(context.Background(), Request{
		Method:      "GET",
		URL:         srv.URL + "/search",
		QueryParams: url.Values{"q": []string{"<script>"}},
	})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	if status != 200 || body != "ok" {
		t.Fatalf("unexpected response: status=%d body=%q", status, body)
	}

	got := <-ch
	if got.method != http.MethodGet {
		t.Fatalf("expected GET request, got %s", got.method)
	}
	if got.url.Query().Get("q") != "<script>" {
		t.Fatalf("expected query param q=<script>, got url=%s", got.url.String())
	}
	if got.body != "" {
		t.Fatalf("expected no request body for GET, got %q", got.body)
	}
	if got.contentType != "" {
		t.Fatalf("expected no Content-Type header for a bodyless GET, got %q", got.contentType)
	}
}

// TestDo_GETWithEmptyMethodDefaultsToGET confirms the pre-TD-#2 zero-value
// behavior is preserved: Request.Method == "" still issues a GET, matching
// the old bare-method-string API's implicit default.
func TestDo_GETWithEmptyMethodDefaultsToGET(t *testing.T) {
	srv, ch := newCaptureServer(t)
	c := New(2 * time.Second)

	_, _, _, _, err := c.Do(context.Background(), Request{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	got := <-ch
	if got.method != http.MethodGet {
		t.Fatalf("expected an empty Method to default to GET, got %q", got.method)
	}
}

// TestDo_POSTSendsFormBodyAndContentType covers item 2 of the required
// TD #2 tests: a POST request encodes FormParams as an
// application/x-www-form-urlencoded body and sets the matching
// Content-Type, with no query parameters for the mutated field.
func TestDo_POSTSendsFormBodyAndContentType(t *testing.T) {
	srv, ch := newCaptureServer(t)
	c := New(2 * time.Second)

	body, status, _, _, err := c.Do(context.Background(), Request{
		Method:     "POST",
		URL:        srv.URL + "/submit",
		FormParams: url.Values{"x": []string{"<script>"}},
	})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	if status != 200 || body != "ok" {
		t.Fatalf("unexpected response: status=%d body=%q", status, body)
	}

	got := <-ch
	if got.method != http.MethodPost {
		t.Fatalf("expected POST request, got %s", got.method)
	}
	if got.contentType != "application/x-www-form-urlencoded" {
		t.Fatalf("expected default Content-Type application/x-www-form-urlencoded, got %q", got.contentType)
	}
	wantBody := url.Values{"x": []string{"<script>"}}.Encode()
	if got.body != wantBody {
		t.Fatalf("expected form-urlencoded body %q, got %q", wantBody, got.body)
	}
	if len(got.url.Query()) != 0 {
		t.Fatalf("expected no query parameters for the mutated POST field, got %v", got.url.Query())
	}
}

// TestDo_POSTContentTypeOverride confirms a caller-supplied ContentType
// wins over the application/x-www-form-urlencoded default.
func TestDo_POSTContentTypeOverride(t *testing.T) {
	srv, ch := newCaptureServer(t)
	c := New(2 * time.Second)

	_, _, _, _, err := c.Do(context.Background(), Request{
		Method:      "POST",
		URL:         srv.URL + "/submit",
		FormParams:  url.Values{"x": []string{"1"}},
		ContentType: "application/x-www-form-urlencoded; charset=utf-8",
	})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	got := <-ch
	if got.contentType != "application/x-www-form-urlencoded; charset=utf-8" {
		t.Fatalf("expected the overridden Content-Type to be sent, got %q", got.contentType)
	}
}

// TestDo_POSTWithNoFormParamsSendsNoBody confirms a POST with an empty
// FormParams sends no body and no Content-Type header, rather than an
// empty-but-present form body.
func TestDo_POSTWithNoFormParamsSendsNoBody(t *testing.T) {
	srv, ch := newCaptureServer(t)
	c := New(2 * time.Second)

	_, _, _, _, err := c.Do(context.Background(), Request{Method: "POST", URL: srv.URL + "/submit"})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	got := <-ch
	if got.body != "" {
		t.Fatalf("expected no body for a POST with no FormParams, got %q", got.body)
	}
	if got.contentType != "" {
		t.Fatalf("expected no Content-Type for a POST with no FormParams, got %q", got.contentType)
	}
}

// TestDo_QueryParamsIgnoredForPOST confirms POST never consults
// QueryParams (only FormParams) - the two are mutually exclusive per
// method, not merged.
func TestDo_QueryParamsIgnoredForPOST(t *testing.T) {
	srv, ch := newCaptureServer(t)
	c := New(2 * time.Second)

	_, _, _, _, err := c.Do(context.Background(), Request{
		Method:      "POST",
		URL:         srv.URL + "/submit",
		QueryParams: url.Values{"leak": []string{"1"}},
		FormParams:  url.Values{"x": []string{"1"}},
	})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	got := <-ch
	if got.url.Query().Get("leak") != "" {
		t.Fatalf("expected QueryParams to be ignored for POST, but %q leaked into the URL query string: %s", "leak", got.url.String())
	}
}
