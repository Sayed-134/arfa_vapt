package httpclient

import (
	"context"
	"io"
	"net/http"
	"time"
)

type Client struct {
	HTTP      *http.Client
	UserAgent string
	MaxBody   int64
}

func New(timeout time.Duration) *Client {
	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 20, MaxConnsPerHost: 20, IdleConnTimeout: 60 * time.Second}
	return &Client{HTTP: &http.Client{Transport: tr, Timeout: timeout}, UserAgent: "Arfa-VAPT/1.0", MaxBody: 4 << 20}
}

func (c *Client) Do(ctx context.Context, method, rawURL string, params map[string]string) (string, int, http.Header, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return "", 0, nil, 0, err
	}
	q := req.URL.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	dur := time.Since(start)
	if err != nil {
		return "", 0, nil, dur, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.MaxBody))
	if err != nil {
		return "", resp.StatusCode, resp.Header, dur, err
	}
	return string(body), resp.StatusCode, resp.Header, dur, nil
}
