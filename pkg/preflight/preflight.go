package preflight

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Status string

const (
	Pass         Status = "pass"
	Timeout      Status = "timeout"
	Fail         Status = "fail"
	Inconclusive Status = "inconclusive"
	Reachable    Status = "reachable"
)

type Check struct {
	Name       string `json:"name"`
	Status     Status `json:"status"`
	Detail     string `json:"detail"`
	DurationMS int64  `json:"duration_ms"`
}

type Result struct {
	Target      string   `json:"target"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
	SelectedURL string   `json:"selected_url,omitempty"`
	Status      Status   `json:"status"`
	Checks      []Check  `json:"checks"`
	Reason      string   `json:"reason"`
}

type Config struct {
	DNSTimeout     time.Duration
	ConnectTimeout time.Duration
	HTTPTimeout    time.Duration
}

func DefaultConfig() Config {
	return Config{DNSTimeout: 3 * time.Second, ConnectTimeout: 5 * time.Second, HTTPTimeout: 8 * time.Second}
}

func Run(ctx context.Context, target string, cfg Config) Result {
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = 3 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 8 * time.Second
	}

	r := Result{Target: target, Status: Inconclusive}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		r.Checks = append(r.Checks, Check{Name: "parse", Status: Fail, Detail: "invalid target URL"})
		r.Reason = "invalid target URL"
		return r
	}
	host := u.Hostname()
	start := time.Now()
	dctx, cancel := context.WithTimeout(ctx, cfg.DNSTimeout)
	ips, err := net.DefaultResolver.LookupHost(dctx, host)
	cancel()
	ch := Check{Name: "dns", DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		ch.Status = Fail
		if strings.Contains(strings.ToLower(err.Error()), "timeout") {
			ch.Status = Timeout
		}
		ch.Detail = err.Error()
		r.Checks = append(r.Checks, ch)
		r.Reason = "DNS resolution failed"
		return r
	}
	r.ResolvedIPs = unique(ips)
	ch.Status = Pass
	ch.Detail = strings.Join(r.ResolvedIPs, ", ")
	r.Checks = append(r.Checks, ch)

	schemes := []string{}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		schemes = append(schemes, strings.ToLower(u.Scheme))
		if u.Scheme == "http" {
			schemes = append(schemes, "https")
		}
		if u.Scheme == "https" {
			schemes = append(schemes, "http")
		}
	default:
		schemes = []string{"https", "http"}
	}

	for _, scheme := range schemes {
		candidate := *u
		candidate.Scheme = scheme
		if candidate.Port() == "" {
			if scheme == "https" {
				candidate.Host = net.JoinHostPort(host, "443")
			} else {
				candidate.Host = net.JoinHostPort(host, "80")
			}
		}
		// Restore a normal URL representation when a non-default explicit port was supplied.
		if u.Port() != "" {
			candidate.Host = u.Host
		}

		port := candidate.Port()
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		addr := net.JoinHostPort(host, port)
		start = time.Now()
		dctx, cancel = context.WithTimeout(ctx, cfg.ConnectTimeout)
		d := net.Dialer{Timeout: cfg.ConnectTimeout}
		conn, derr := d.DialContext(dctx, "tcp", addr)
		cancel()
		cc := Check{Name: "tcp:" + port, DurationMS: time.Since(start).Milliseconds()}
		if derr != nil {
			cc.Status = Fail
			if strings.Contains(strings.ToLower(derr.Error()), "timeout") || ctx.Err() != nil {
				cc.Status = Timeout
			}
			cc.Detail = derr.Error()
			r.Checks = append(r.Checks, cc)
			continue
		}
		_ = conn.Close()
		cc.Status = Pass
		cc.Detail = "connection established"
		r.Checks = append(r.Checks, cc)

		httpClient := &http.Client{Timeout: cfg.HTTPTimeout, Transport: &http.Transport{
			Proxy:        http.ProxyFromEnvironment,
			MaxIdleConns: 4, MaxConnsPerHost: 2, IdleConnTimeout: 15 * time.Second,
		}}
		reqCtx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout)
		req, e := http.NewRequestWithContext(reqCtx, http.MethodHead, candidate.String(), nil)
		if e != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Arfa-VAPT-Preflight/2.0")
		req.Header.Set("Accept", "*/*")
		start = time.Now()
		resp, herr := httpClient.Do(req)
		dur := time.Since(start).Milliseconds()
		if herr != nil {
			// Some servers reject HEAD; retry once with GET using the same bounded timeout.
			_ = req.Body
			cancel()
			reqCtx, cancel = context.WithTimeout(ctx, cfg.HTTPTimeout)
			req, _ = http.NewRequestWithContext(reqCtx, http.MethodGet, candidate.String(), nil)
			req.Header.Set("User-Agent", "Arfa-VAPT-Preflight/2.0")
			req.Header.Set("Accept", "*/*")
			start = time.Now()
			resp, herr = httpClient.Do(req)
			dur = time.Since(start).Milliseconds()
		}
		cancel()
		hc := Check{Name: "http", DurationMS: dur}
		if herr != nil {
			hc.Status = Fail
			if strings.Contains(strings.ToLower(herr.Error()), "timeout") {
				hc.Status = Timeout
			}
			hc.Detail = herr.Error()
			r.Checks = append(r.Checks, hc)
			continue
		}
		resp.Body.Close()
		hc.Status = Pass
		hc.Detail = fmt.Sprintf("HTTP %d %s", resp.StatusCode, resp.Status)
		r.Checks = append(r.Checks, hc)
		r.SelectedURL = candidate.String()
		r.Status = Reachable
		r.Reason = "target reachable"
		return r
	}
	r.Reason = "no HTTP/HTTPS candidate completed a TCP connection and HTTP baseline"
	return r
}

func unique(in []string) []string {
	m := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}
