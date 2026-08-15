package detectors

import (
	"arfa/pkg/models"
	"context"
	"fmt"
	"strings"
)

type XSS struct{}

func (XSS) Name() string     { return "XSS" }
func (XSS) Category() string { return "XSS" }
func (XSS) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return strings.Contains(pr.Body, p.Value)
}
func (d XSS) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("XSS", "Reflected Cross-Site Scripting", "High", "8.2", "Medium", ep, param, p, pr, "Payload reflected in response; context requires verification"))
		}
	}
	return o
}

type SQLi struct{}

func (SQLi) Name() string     { return "SQLi" }
func (SQLi) Category() string { return "SQLi" }
func (SQLi) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return containsFold(pr.Body, "sql syntax", "mysql_fetch", "sqlite error", "postgresql", "odbc sql", "unclosed quotation", "you have an error in your sql") && strings.ContainsAny(p.Value, "'\"")
}
func (d SQLi) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("SQLi", "SQL Injection", "Critical", "9.8", "High", ep, param, p, pr, "Database error signature correlated with injected input"))
		}
	}
	return o
}

type LFI struct{}

func (LFI) Name() string     { return "LFI" }
func (LFI) Category() string { return "LFI" }
func (LFI) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return (strings.Contains(p.Value, "passwd") || strings.Contains(p.Value, "../") || strings.Contains(p.Value, "etc")) && containsOutsidePayload(pr.Body, p.Value, "root:x:", "/etc/passwd", "[boot loader]", "document_root")
}
func (d LFI) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("LFI", "Local File Inclusion", "High", "7.5", "High", ep, param, p, pr, "File-content marker correlated with injected input"))
		}
	}
	return o
}

type RCE struct{}

func (RCE) Name() string     { return "RCE" }
func (RCE) Category() string { return "RCE" }
func (RCE) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return strings.ContainsAny(p.Value, "|;&`$") && containsOutsidePayload(pr.Body, p.Value, "arfa-rce-marker", "uid=", "gid=")
}
func (d RCE) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("RCE", "Command Injection", "Critical", "10.0", "Medium", ep, param, p, pr, "Command-execution marker in response"))
		}
	}
	return o
}

type SSTI struct{}

func (SSTI) Name() string     { return "SSTI" }
func (SSTI) Category() string { return "SSTI" }
func (SSTI) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return strings.Contains(pr.Body, "SSTI-MARKER")
}
func (d SSTI) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("SSTI", "Server-Side Template Injection", "Critical", "9.8", "High", ep, param, p, pr, "Template evaluation marker detected"))
		}
	}
	return o
}

type SSRF struct{}

func (SSRF) Name() string     { return "SSRF" }
func (SSRF) Category() string { return "SSRF" }
func (SSRF) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return containsFold(pr.Body, "ssrf-marker", "instance-id", "ami-id")
}
func (d SSRF) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("SSRF", "Server-Side Request Forgery", "High", "8.0", "Medium", ep, param, p, pr, "Server-side request marker detected"))
		}
	}
	return o
}

type XXE struct{}

func (XXE) Name() string     { return "XXE" }
func (XXE) Category() string { return "XXE" }
func (XXE) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	lv := strings.ToLower(p.Value)
	return (strings.Contains(lv, "<!doctype") || strings.Contains(lv, "<!entity") || strings.Contains(lv, "<?xml")) && containsOutsidePayload(pr.Body, p.Value, "xxe-marker")
}
func (d XXE) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("XXE", "XML External Entity Injection", "High", "8.1", "Medium", ep, param, p, pr, "External entity/file marker detected"))
		}
	}
	return o
}

type CRLF struct{}

func (CRLF) Name() string     { return "CRLF" }
func (CRLF) Category() string { return "CRLF" }
func (CRLF) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	return pr.Headers.Get("X-Arfa-Injected") == "true"
}
func (d CRLF) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("CRLF", "CRLF Injection", "Medium", "6.1", "High", ep, param, p, pr, "Injected response header observed"))
		}
	}
	return o
}

type Redirect struct{}

func (Redirect) Name() string     { return "Open Redirect" }
func (Redirect) Category() string { return "Open Redirect" }
func (Redirect) HasEvidence(ep models.Endpoint, pr models.ProbeResult, p models.Payload) bool {
	loc := pr.Headers.Get("Location")
	return loc != "" && !strings.Contains(loc, ep.URL)
}
func (d Redirect) Detect(ctx context.Context, ep models.Endpoint, p models.Payload, probe Probe) []models.Finding {
	var o []models.Finding
	for _, param := range params(ep) {
		pr := probe(ctx, ep.URL, ep.Method, inject(ep, param, p.Value), p)
		if pr.Err != nil {
			continue
		}
		loc := pr.Headers.Get("Location")
		if d.HasEvidence(ep, pr, p) {
			o = append(o, baseFinding("Open Redirect", "Open Redirect", "Medium", "6.1", "High", ep, param, p, pr, fmt.Sprintf("Location: %s", loc)))
		}
	}
	return o
}
