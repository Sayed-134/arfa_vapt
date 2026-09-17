package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	HTTP      *http.Client
	UserAgent string
	MaxBody   int64
}

// Request describes one outbound probe/crawl request. It is deliberately a
// flat struct (no BodyType/BodyStrategy abstraction - see TD #2 decision
// log in PLATFORM_STRATEGY.md §12.4): callers set exactly the fields that
// matter for the method they are using and leave the rest at their zero
// value.
//
//   - GET  (or any non-POST method): QueryParams are encoded onto the URL
//     query string; no request body is sent.
//   - POST: FormParams are encoded as an application/x-www-form-urlencoded
//     request body; the URL's own query string (if any) is left untouched,
//     but QueryParams is not consulted for POST.
//
// ContentType overrides the Content-Type header sent with a POST body.
// When empty and FormParams is non-empty, Do defaults it to
// "application/x-www-form-urlencoded".
type Request struct {
	Method      string
	URL         string
	QueryParams url.Values
	FormParams  url.Values
	ContentType string
}

func New(timeout time.Duration) *Client {
	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 20, MaxConnsPerHost: 20, IdleConnTimeout: 60 * time.Second}
	return &Client{HTTP: &http.Client{Transport: tr, Timeout: timeout}, UserAgent: "Arfa-VAPT/1.0", MaxBody: 4 << 20}
}

// Do issues one HTTP request described by r. See Request's doc comment for
// how method selects between query-string and form-body parameter
// transport. Method defaults to GET when empty, matching the previous
// zero-value behavior of a bare method string.
func (c *Client) Do(ctx context.Context, r Request) (string, int, http.Header, time.Duration, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	reqURL := r.URL
	var body io.Reader
	contentType := ""

	if strings.EqualFold(method, http.MethodPost) {
		if len(r.FormParams) > 0 {
			body = strings.NewReader(r.FormParams.Encode())
			contentType = r.ContentType
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
		}
	} else if len(r.QueryParams) > 0 {
		u, err := url.Parse(reqURL)
		if err != nil {
			return "", 0, nil, 0, err
		}
		q := u.Query()
		for k, vs := range r.QueryParams {
			for _, v := range vs {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return "", 0, nil, 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	dur := time.Since(start)
	if err != nil {
		return "", 0, nil, dur, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, c.MaxBody))
	if err != nil {
		return "", resp.StatusCode, resp.Header, dur, err
	}
	return string(respBody), resp.StatusCode, resp.Header, dur, nil
}
