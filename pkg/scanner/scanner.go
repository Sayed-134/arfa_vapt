package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"arfa/pkg/adaptive"
	"arfa/pkg/coverage"
	"arfa/pkg/crawler"
	"arfa/pkg/detectors"
	"arfa/pkg/httpclient"
	"arfa/pkg/models"
	"arfa/pkg/payloads"
	"arfa/pkg/planner"
	"arfa/pkg/preflight"
	"arfa/pkg/ratelimiter"
	"arfa/pkg/verification"
)

// evidenceSnippetLimit bounds how much of a response body ever appears in a
// Finding's structured evidence - see models.Evidence's doc comment for the
// redaction rationale. The full body is never stored; ResponseHash lets two
// findings be compared without it.
const evidenceSnippetLimit = 500

// defaultMaxJobs is the hard ceiling on how many probe jobs a single scan
// will schedule, regardless of Mode/endpoint/payload count. It exists so a
// pathological Deep scan (many endpoints x large payload corpus x multiple
// encodings) cannot silently balloon into an unbounded amount of work; see
// Config.MaxJobs to override it.
const defaultMaxJobs = 500_000

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

	// MaxJobs bounds how many probe jobs a single Scan call will schedule.
	// 0 uses defaultMaxJobs. This does not change what Quick/Standard/Deep
	// mode select (their existing per-category budgets are unchanged); it
	// is a last-resort ceiling for pathological combinations (many
	// endpoints x large payload corpus x multiple encodings) so a scan
	// degrades to "capped, and clearly reported as capped" instead of
	// materializing unbounded work.
	MaxJobs int
}

type Scanner struct {
	cfg      Config
	http     Transport
	crawl    CrawlerIface
	reg      *detectors.Registry
	lim      *ratelimiter.Limiter
	verifier Verifier
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
	if cfg.MaxJobs <= 0 {
		cfg.MaxJobs = defaultMaxJobs
	}
	hc := httpclient.New(cfg.Timeout)
	return &Scanner{cfg: cfg, http: hc, crawl: crawler.New(hc, cfg.MaxPages), reg: reg, lim: ratelimiter.New(cfg.Rate), verifier: defaultVerifier}
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

	// cov tracks endpoint x parameter x vulnerability-class coverage. Seed
	// every combination the scheduler is aware of *before* any probe runs,
	// so the final snapshot also shows what was never attempted at all
	// (e.g. a category with zero payloads loaded for this Mode) - not just
	// cells that happened to produce a finding.
	cov := coverage.New()
	for _, ep := range endpoints {
		for _, det := range s.reg.All() {
			for _, param := range effectiveParams(ep) {
				cov.Seed(coverage.Key{Endpoint: ep.URL, Parameter: param, Category: det.Category()})
			}
		}
		// IDOR is a separate heuristic phase (see below), not a registered
		// Detector, and it only ever considers an endpoint's *actually
		// discovered* parameters (never the generic q/id/search fallback
		// list) - see pkg/detectors/idor.go.
		for _, param := range ep.Parameters {
			cov.Seed(coverage.Key{Endpoint: ep.URL, Parameter: param, Category: "IDOR"})
		}
	}

	totalJobs := countJobs(endpoints, s.reg.All(), s.selectPayloads, s.cfg.Mode)
	if totalJobs == 0 {
		result.Stats.DurationMS = time.Since(start).Milliseconds()
		result.Coverage = cov.Snapshot()
		result.NextActions = planner.Plan(result.Coverage, planner.DefaultMaxActions)
		return result, nil
	}

	plannedJobs := totalJobs
	capped := false
	if int64(plannedJobs) > int64(s.cfg.MaxJobs) {
		plannedJobs = s.cfg.MaxJobs
		capped = true
	}

	workers := s.cfg.Workers
	if workers > plannedJobs {
		workers = plannedJobs
	}
	// ctrl hands out a bounded number of concurrency permits and shrinks or
	// grows that number based on the observed error/throttle rate (429,
	// 403, timeouts, connection failures). The underlying worker pool size
	// (goroutine count) stays fixed at `workers`; ctrl only changes how many
	// of those workers can be doing real work at once. See pkg/adaptive.
	ctrl := adaptive.New(workers)

	// jobsCh is unbuffered and fed by a producer goroutine (below) that
	// generates jobs on the fly from the same nested endpoint/detector/
	// payload/parameter/encoding structure the old code used to fully
	// materialize into a slice up front. With an unbuffered channel, at
	// most one job per worker is ever alive in memory at a time - the
	// producer blocks on send until a worker is ready, so job count is
	// bounded by concurrency, not by corpus size. See countJobs/streamJobs.
	jobsCh := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	findings := make([]models.Finding, 0)

	// verifyCache is scoped to this single Scan call (never reused across
	// scans/targets - see verification.Cache's doc comment) so that
	// verifying an identical candidate twice within one scan reuses the
	// first repeat+control probe outcome instead of repeating it. This is
	// the minimal integration point for ARCHITECTURE.md §11's Verification
	// Result Cache requirement.
	verifyCache := verification.NewCache()

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
				covKey := coverage.Key{Endpoint: j.ep.URL, Parameter: param, Category: j.detector.Category()}

				pr := s.rawProbe(ctx, ctrl, j.ep, param, j.payload.Value, countReq)
				if pr.Err != nil {
					continue
				}
				// A completed probe is an attempt regardless of whether it
				// produces a finding - Mark only ever strengthens a cell
				// (see coverage.Tracker), so a later Verified/Failed/
				// Inconclusive observation below still wins.
				cov.Mark(covKey, models.CoverageAttempted)

				normalized := verification.Normalize(j.payload, pr)
				callback := func(_ context.Context, _ string, _ string, _ map[string]string, _ models.Payload) models.ProbeResult {
					return normalized
				}
				found := j.detector.Detect(ctx, j.ep, j.payload, callback)
				for _, f := range found {
					f.Encoding = j.encoding
					f.VerificationStatus = detectors.Unverified
					var vres *verification.Result

					// Detection != confirmation: re-run the detector's own
					// evidence check against an independent repeat probe
					// and a benign control probe before this finding is
					// allowed to claim anything stronger than "candidate".
					if ec, ok := j.detector.(detectors.EvidenceChecker); ok {
						evidenceCheck := func(vpr models.ProbeResult) bool {
							return ec.HasEvidence(j.ep, vpr, j.payload)
						}
						cacheKey := verification.CacheKey(j.detector.Category(), j.ep.URL, param, j.payload.Value)
						// GetOrCompute (not a separate Get+Set) is what
						// makes this atomic: two workers racing on the same
						// cacheKey must not both fall through to Verify.
						v := verifyCache.GetOrCompute(cacheKey, func() verification.Result {
							return s.verifier.Verify(ctx, j.ep, param, j.payload.Value, evidenceCheck, verifyProbe)
						})
						vres = &v
						f.VerificationStatus = string(v.Status)
						f.VerificationDetail = v.Detail
						f.VerificationConfidence = string(v.Confidence)
						f.VerificationConfidenceReason = v.ConfidenceReason
					}

					f.ID = fingerprint(f)
					f.EvidenceDetail = buildEvidence(j.detector.Category(), j.ep, param, pr, vres)
					cov.Mark(covKey, coverage.FromVerificationStatus(f.VerificationStatus))
					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()
				}
			}
		}()
	}

	go streamJobs(ctx, jobsCh, endpoints, s.reg.All(), s.selectPayloads, s.cfg.Mode, plannedJobs)
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
			idorFindings := detectors.ScanIDOR(ctx, ep, idorProbe)
			for _, f := range idorFindings {
				f.ID = fingerprint(f)
				findings = append(findings, f)
			}
			// Coarse but honest: ScanIDOR privately decides per-parameter
			// whether a numeric value was present to mutate, so this marks
			// every discovered parameter on the endpoint as at least
			// Attempted for IDOR once the phase has run over it; any
			// parameter that actually produced a finding is additionally
			// upgraded to Inconclusive (IDOR findings are always
			// UNVERIFIED - see idor.go - which maps to Inconclusive).
			for _, param := range ep.Parameters {
				cov.Mark(coverage.Key{Endpoint: ep.URL, Parameter: param, Category: "IDOR"}, models.CoverageAttempted)
			}
			for _, f := range idorFindings {
				cov.Mark(coverage.Key{Endpoint: f.Endpoint, Parameter: f.Parameter, Category: "IDOR"}, coverage.FromVerificationStatus(f.VerificationStatus))
			}
		}
	}

	result.Findings = dedup(findings)
	result.Stats.AdaptiveBudget = ctrl.Budget()
	result.Stats.DurationMS = time.Since(start).Milliseconds()
	result.Stats.JobsPlanned = int64(plannedJobs)
	result.Stats.JobsCapped = capped
	result.Coverage = cov.Snapshot()
	result.NextActions = planner.Plan(result.Coverage, planner.DefaultMaxActions)
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

// walkJobs iterates the endpoint x detector x payload x parameter x
// encoding combination space in a fixed, deterministic order, calling
// visit for each one without ever materializing them all into a slice.
// visit returns false to stop iteration early - used to honor
// Config.MaxJobs and context cancellation. Both counting (countJobs) and
// actually running jobs (streamJobs) share this single walk so a capped
// scan's "first N jobs" are identical to the first N jobs an uncapped scan
// would have run, in the same order the pre-Milestone-2 code produced.
func walkJobs(endpoints []models.Endpoint, dets []detectors.Detector, selectPayloads func(string) []models.Payload, mode Mode, visit func(job) bool) {
	for _, ep := range endpoints {
		for _, det := range dets {
			for _, pl := range selectPayloads(det.Category()) {
				for _, param := range effectiveParams(ep) {
					for _, enc := range encodings(det.Category(), mode) {
						ep2 := ep
						ep2.Parameters = []string{param}
						p2 := pl
						p2.Value = encode(pl.Value, enc)
						if !visit(job{ep: ep2, detector: det, payload: p2, encoding: enc}) {
							return
						}
					}
				}
			}
		}
	}
}

// countJobs computes the total job count without allocating a job struct
// for each one - used only to size the worker pool and to report
// Stats.JobsPlanned/decide Stats.JobsCapped before streaming begins.
func countJobs(endpoints []models.Endpoint, dets []detectors.Detector, selectPayloads func(string) []models.Payload, mode Mode) int {
	n := 0
	walkJobs(endpoints, dets, selectPayloads, mode, func(job) bool {
		n++
		return true
	})
	return n
}

// streamJobs generates jobs on the fly and sends each one on jobsCh,
// closing it when done. Because jobsCh is unbuffered, this blocks until a
// worker is ready for each job - at most one job per worker is ever alive
// in memory at once, regardless of how large the full combination space
// is. Stops early (without sending further jobs) once limit jobs have been
// sent, or immediately if ctx is canceled.
func streamJobs(ctx context.Context, jobsCh chan job, endpoints []models.Endpoint, dets []detectors.Detector, selectPayloads func(string) []models.Payload, mode Mode, limit int) {
	defer close(jobsCh)
	sent := 0
	walkJobs(endpoints, dets, selectPayloads, mode, func(j job) bool {
		if sent >= limit {
			return false
		}
		select {
		case jobsCh <- j:
			sent++
			return true
		case <-ctx.Done():
			return false
		}
	})
}

// buildEvidence assembles the structured, redaction-bounded evidence record
// for a finding. See models.Evidence's doc comment for what is deliberately
// excluded (raw headers, full response bodies) and why.
func buildEvidence(category string, ep models.Endpoint, param string, pr models.ProbeResult, vres *verification.Result) *models.Evidence {
	snippet := pr.Body
	if len(snippet) > evidenceSnippetLimit {
		snippet = snippet[:evidenceSnippetLimit]
	}
	sum := sha256.Sum256([]byte(pr.Body))
	ev := &models.Evidence{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Endpoint:        ep.URL,
		Parameter:       param,
		Category:        category,
		RequestMethod:   ep.Method,
		RequestURL:      pr.URL,
		ResponseStatus:  pr.Status,
		ResponseSnippet: snippet,
		ResponseHash:    hex.EncodeToString(sum[:]),
	}
	if vres != nil {
		if vres.RepeatProbe != nil {
			ev.VerificationTrace = append(ev.VerificationTrace, fmt.Sprintf("repeat probe: status %d, %d byte response", vres.RepeatProbe.Status, len(vres.RepeatProbe.Body)))
		}
		if vres.ControlProbe != nil {
			ev.VerificationTrace = append(ev.VerificationTrace, fmt.Sprintf("control probe: status %d, %d byte response", vres.ControlProbe.Status, len(vres.ControlProbe.Body)))
		}
		ev.VerificationTrace = append(ev.VerificationTrace, fmt.Sprintf("verdict: %s - %s", vres.Status, vres.Detail))
	}
	return ev
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
