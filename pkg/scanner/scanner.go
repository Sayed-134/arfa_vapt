package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sort"
	"sync"
	"time"

	"arfa/pkg/adaptive"
	"arfa/pkg/crawler"
	"arfa/pkg/detectors"
	"arfa/pkg/httpclient"
	"arfa/pkg/models"
	"arfa/pkg/payloads"
	"arfa/pkg/preflight"
	"arfa/pkg/ratelimiter"
	"arfa/pkg/verification"
)

type Mode string

const (
	Quick    Mode = "quick"
	Standard Mode = "standard"
	Deep     Mode = "deep"
)

type Config struct {
	Workers       int
	Rate          float64
	Timeout       time.Duration
	Mode          Mode
	MaxPages      int
	Verbose       bool
	PreflightOnly bool
	SkipPreflight bool
	Scope         models.ScanScope
}

type Scanner struct {
	cfg      Config
	http     *httpclient.Client
	crawl    *crawler.Crawler
	reg      *detectors.Registry
	lim      *ratelimiter.Limiter
	payloads map[string][]models.Payload
}

func New(cfg Config, reg *detectors.Registry) *Scanner {
	if cfg.Workers < 1 {
		cfg.Workers = 10
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 12 * time.Second
	}
	if cfg.MaxPages < 1 {
		cfg.MaxPages = 30
	}
	hc := httpclient.New(cfg.Timeout)
	return &Scanner{cfg: cfg, http: hc, crawl: crawler.New(hc, cfg.MaxPages), reg: reg, lim: ratelimiter.New(cfg.Rate)}
}

func (s *Scanner) LoadPayloads(root string) error {
	p, err := payloads.Load(root)
	if err != nil {
		return err
	}
	s.payloads = payloads.Group(p)
	return nil
}

func (s *Scanner) Scan(ctx context.Context, target string) (models.ScanResult, error) {
	start := time.Now()
	result := models.ScanResult{SchemaVersion: "arfa.scan/v1", Target: target, Scope: s.cfg.Scope, StartedAt: start.UTC().Format(time.RFC3339), Mode: string(s.cfg.Mode)}

	if !s.cfg.SkipPreflight {
		pf := preflight.Run(ctx, target, preflight.DefaultConfig())
		checks := make([]models.ReachabilityCheck, 0, len(pf.Checks))
		for _, c := range pf.Checks {
			checks = append(checks, models.ReachabilityCheck{Name: c.Name, Status: string(c.Status), Detail: c.Detail, DurationMS: c.DurationMS})
		}
		result.Reachability = models.Reachability{
			Status:      string(pf.Status),
			Reason:      pf.Reason,
			ResolvedIPs: pf.ResolvedIPs,
			SelectedURL: pf.SelectedURL,
			Checks:      checks,
		}
		if s.cfg.PreflightOnly {
			result.Stats.DurationMS = time.Since(start).Milliseconds()
			return result, nil
		}
		if pf.Status != preflight.Reachable {
			result.Stats.DurationMS = time.Since(start).Milliseconds()
			return result, nil
		}
	} else {
		result.Reachability = models.Reachability{Status: "skipped", Reason: "preflight disabled"}
	}

	endpoints, pages, err := s.crawl.Crawl(ctx, target)
	if err != nil {
		return result, err
	}
	result.Stats.Pages = pages
	result.Stats.Endpoints = len(endpoints)
	result.Stats.Parameters = countParams(endpoints)

	jobs := make([]job, 0)
	for _, ep := range endpoints {
		for _, det := range s.reg.All() {
			for _, pl := range s.selectPayloads(det.Category()) {
				for _, param := range effectiveParams(ep) {
					for _, enc := range encodings(det.Category(), s.cfg.Mode) {
						ep2 := ep
						ep2.Parameters = []string{param}
						p2 := pl
						p2.Value = encode(pl.Value, enc)
						jobs = append(jobs, job{ep: ep2, detector: det, payload: p2, encoding: enc})
					}
				}
			}
		}
	}

	if len(jobs) == 0 {
		result.Stats.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	workers := s.cfg.Workers
	if workers > len(jobs) {
		workers = len(jobs)
	}
	// ctrl hands out a bounded number of concurrency permits and shrinks or
	// grows that number based on the observed error/throttle rate (429,
	// 403, timeouts, connection failures). The underlying worker pool size
	// (goroutine count) stays fixed at `workers`; ctrl only changes how many
	// of those workers can be doing real work at once. See pkg/adaptive.
	ctrl := adaptive.New(workers)

	jobsCh := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	findings := make([]models.Finding, 0)

	countReq := func(pr models.ProbeResult) {
		mu.Lock()
		result.Stats.Requests++
		if pr.Err != nil {
			result.Stats.Errors++
		}
		mu.Unlock()
	}

	// verifyProbe is shared by the per-job verification step and, later,
	// the IDOR phase. It routes every additional request through the same
	// HTTP client, rate limiter, and adaptive controller as the main scan.
	verifyProbe := func(vctx context.Context, vep models.Endpoint, vparam, vvalue string) models.ProbeResult {
		return s.rawProbe(vctx, ctrl, vep, vparam, vvalue, countReq)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				if ctx.Err() != nil {
					return
				}
				param := j.ep.Parameters[0]
				pr := s.rawProbe(ctx, ctrl, j.ep, param, j.payload.Value, countReq)
				if pr.Err != nil {
					continue
				}
				normalized := verification.Normalize(j.payload, pr)
				callback := func(_ context.Context, _ string, _ string, _ map[string]string, _ models.Payload) models.ProbeResult {
					return normalized
				}
				found := j.detector.Detect(ctx, j.ep, j.payload, callback)
				for _, f := range found {
					f.Encoding = j.encoding
					f.VerificationStatus = detectors.Unverified

					// Detection != confirmation: re-run the detector's own
					// evidence check against an independent repeat probe
					// and a benign control probe before this finding is
					// allowed to claim anything stronger than "candidate".
					if ec, ok := j.detector.(detectors.EvidenceChecker); ok {
						evidenceCheck := func(vpr models.ProbeResult) bool {
							return ec.HasEvidence(j.ep, vpr, j.payload)
						}
						vres := verification.Verify(ctx, j.ep, param, j.payload.Value, evidenceCheck, verifyProbe)
						f.VerificationStatus = string(vres.Status)
						f.VerificationDetail = vres.Detail
					}

					f.ID = fingerprint(f)
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		defer close(jobsCh)
		for _, j := range jobs {
			select {
			case jobsCh <- j:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()

	// IDOR/BOLA heuristic phase: numeric-identifier differential analysis.
	// This does not go through the detector/payload job pipeline above
	// because it needs each endpoint's *original* parameter value to
	// mutate, not a line from the payload database (the PayloadsAllTheThings
	// "Insecure Direct Object References" entry is methodology text, not a
	// wordlist). Findings from this phase are always VerificationStatus
	// UNVERIFIED — see pkg/detectors/idor.go for why.
	if ctx.Err() == nil {
		idorProbe := func(vctx context.Context, vep models.Endpoint, vparam, vvalue string) models.ProbeResult {
			return s.rawProbe(vctx, ctrl, vep, vparam, vvalue, countReq)
		}
		for _, ep := range endpoints {
			if ctx.Err() != nil {
				break
			}
			for _, f := range detectors.ScanIDOR(ctx, ep, idorProbe) {
				f.ID = fingerprint(f)
				findings = append(findings, f)
			}
		}
	}

	result.Findings = dedup(findings)
	result.Stats.AdaptiveBudget = ctrl.Budget()
	result.Stats.DurationMS = time.Since(start).Milliseconds()
	sort.Slice(result.Findings, func(i, j int) bool {
		return severity(result.Findings[i].Severity) > severity(result.Findings[j].Severity)
	})
	return result, nil
}

type job struct {
	ep       models.Endpoint
	detector detectors.Detector
	payload  models.Payload
	encoding string
}

// rawProbe is the single low-level HTTP entry point used by the main scan
// loop, the verification engine, and the IDOR phase. Centralizing it here
// means every additional request — not just the first probe per job —
// respects the same rate limiter and adaptive concurrency budget, and is
// counted in the same stats via onDone.
func (s *Scanner) rawProbe(ctx context.Context, ctrl *adaptive.Controller, ep models.Endpoint, param, value string, onDone func(models.ProbeResult)) models.ProbeResult {
	ctrl.Acquire()
	defer ctrl.Release()
	_ = s.lim.Wait(ctx)
	body, status, headers, duration, err := s.http.Do(ctx, ep.Method, ep.URL, map[string]string{param: value})
	s.lim.Feedback(status, err)
	pr := models.ProbeResult{URL: ep.URL, Method: ep.Method, Status: status, Headers: headers, Body: body, DurationMS: duration.Milliseconds(), Err: err}
	throttled := err != nil || status == 429 || status == 403
	ctrl.Report(throttled)
	if onDone != nil {
		onDone(pr)
	}
	return pr
}

func (s *Scanner) selectPayloads(category string) []models.Payload {
	ps := s.payloads[category]
	if s.cfg.Mode == Deep {
		return ps
	}
	// Scheduling budget, not deletion: the complete repository remains available
	// to Deep mode. Quick/Standard merely decide how much of the repository is
	// exercised at each stage.
	quickBudget := map[string]int{"XSS": 50, "SQLi": 50, "LFI": 30, "RCE": 30, "SSRF": 20, "SSTI": 20, "XXE": 15, "CRLF": 15, "Open Redirect": 15}
	standardBudget := map[string]int{"XSS": 200, "SQLi": 200, "LFI": 100, "RCE": 100, "SSRF": 60, "SSTI": 60, "XXE": 40, "CRLF": 40, "Open Redirect": 40}
	limit := standardBudget[category]
	if s.cfg.Mode == Quick {
		limit = quickBudget[category]
	}
	if limit <= 0 || limit > len(ps) {
		limit = len(ps)
	}
	return ps[:limit]
}

func effectiveParams(ep models.Endpoint) []string {
	if len(ep.Parameters) > 0 {
		return ep.Parameters
	}
	return []string{"q", "id", "search", "page", "url"}
}
func countParams(eps []models.Endpoint) int {
	n := 0
	for _, ep := range eps {
		n += len(ep.Parameters)
	}
	return n
}
func encodings(category string, mode Mode) []string {
	if mode == Deep {
		return []string{"plain", "url", "double_url"}
	}
	switch category {
	case "XSS", "SQLi", "LFI", "RCE":
		if mode == Quick {
			return []string{"plain"}
		}
		return []string{"plain", "url"}
	default:
		return []string{"plain"}
	}
}
func encode(v, enc string) string {
	if enc == "url" {
		return urlEscape(v)
	}
	if enc == "double_url" {
		return urlEscape(urlEscape(v))
	}
	return v
}
func urlEscape(v string) string {
	const hex = "0123456789ABCDEF"
	b := make([]byte, 0, len(v)*3)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b = append(b, c)
		} else {
			b = append(b, '%')
			b = append(b, hex[c>>4], hex[c&15])
		}
	}
	return string(b)
}
func dedup(fs []models.Finding) []models.Finding {
	m := map[string]models.Finding{}
	for _, f := range fs {
		if _, ok := m[f.ID]; !ok {
			m[f.ID] = f
		}
	}
	o := make([]models.Finding, 0, len(m))
	for _, f := range m {
		o = append(o, f)
	}
	return o
}
func fingerprint(f models.Finding) string {
	h := sha256.Sum256([]byte(f.Category + "|" + f.Endpoint + "|" + f.Parameter + "|" + f.Evidence))
	return hex.EncodeToString(h[:8])
}
func severity(s string) int {
	switch s {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	}
	return 0
}
func (s *Scanner) LogStats() {
	log.Printf("payload categories=%d limiter=%s", len(s.payloads), s.lim.Interval())
}
