package scanner

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"arfa/pkg/detectors"
	"arfa/pkg/models"
)

// slowFakeTransport simulates a probe that takes measurable, non-trivial
// time to complete and does not itself react to ctx cancellation - the
// same way a real in-flight HTTP request already committed to the wire
// would not vanish the instant a deadline elapses. active tracks how many
// calls are currently in progress, so tests can assert that zero calls are
// still in flight once Scan() has returned - direct proof that every
// worker goroutine that started a probe also finished it and exited,
// rather than inferring shutdown indirectly from runtime.NumGoroutine().
type slowFakeTransport struct {
	sleep  time.Duration
	active int32
	calls  int32
}

func (f *slowFakeTransport) Do(ctx context.Context, method, rawURL string, params map[string]string) (string, int, http.Header, time.Duration, error) {
	atomic.AddInt32(&f.active, 1)
	atomic.AddInt32(&f.calls, 1)
	time.Sleep(f.sleep)
	atomic.AddInt32(&f.active, -1)
	return "<html><body>static page, no form</body></html>", 200, http.Header{}, f.sleep, nil
}

// slowFakeCrawler simulates a crawl phase that is itself slow enough to run
// past an internal MaxDuration deadline. It deliberately returns an error
// referencing ctx.Err() once the sleep completes, mirroring how a real
// crawler's underlying HTTP calls would surface a context-deadline error
// rather than silently succeeding.
type slowFakeCrawler struct {
	sleep time.Duration
}

func (f slowFakeCrawler) Crawl(ctx context.Context, target string) ([]models.Endpoint, int, error) {
	time.Sleep(f.sleep)
	if ctx.Err() != nil {
		return nil, 0, errors.New("crawl aborted: " + ctx.Err().Error())
	}
	return []models.Endpoint{{URL: target, Method: "GET"}}, 1, nil
}

func newMaxDurationTestScanner(t *testing.T, cfg Config, ft *slowFakeTransport) *Scanner {
	t.Helper()
	reg := detectors.NewRegistry(detectors.XSS{})
	s := New(cfg, reg)
	s.payloads = map[string][]models.Payload{
		"XSS": {{ID: "t1", Category: "XSS", Value: "<xsstestmarker>"}},
	}
	s.crawl = fakeCrawler{eps: []models.Endpoint{{URL: "http://fake.invalid/page", Method: "GET"}}, pages: 1}
	s.http = ft
	return s
}

// --- 1. MaxDuration stops scheduling and reports it -----------------------

func TestScan_MaxDurationStopsSchedulingAndReportsExhausted(t *testing.T) {
	// No explicit parameters on the fake endpoint, so effectiveParams falls
	// back to its 5-entry guess list (q, id, search, page, url), giving 5
	// jobs (1 detector x 1 payload x 5 params x 1 encoding in Quick mode).
	// A single worker plus a per-job sleep well above MaxDuration guarantees
	// the budget elapses before all 5 jobs can run.
	ft := &slowFakeTransport{sleep: 40 * time.Millisecond}
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxDuration: 90 * time.Millisecond}
	s := newMaxDurationTestScanner(t, cfg, ft)

	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("expected a MaxDuration timeout to be graceful (no error), got: %v", err)
	}
	if !result.Stats.TimeBudgetExhausted {
		t.Fatal("expected Stats.TimeBudgetExhausted=true when MaxDuration elapses mid-scan")
	}
	calls := atomic.LoadInt32(&ft.calls)
	if calls == 0 {
		t.Fatal("expected at least one probe to have run before the deadline")
	}
	if calls >= 5 {
		t.Fatalf("expected fewer than all 5 planned jobs to run once MaxDuration elapsed, got %d probe calls", calls)
	}
	// The result must still be a valid, usable partial ScanEnvelope: no nil
	// slices that would render as JSON `null` instead of `[]`, and the
	// scheduling stats (computed up front, independent of timing) intact.
	if result.Findings == nil {
		t.Fatal("expected a non-nil (possibly empty) Findings slice in the partial result")
	}
	if result.Coverage == nil {
		t.Fatal("expected a non-nil Coverage snapshot in the partial result")
	}
	if result.Stats.JobsPlanned != 5 {
		t.Fatalf("expected JobsPlanned=5 (unaffected by MaxDuration, only MaxJobs), got %d", result.Stats.JobsPlanned)
	}
}

// --- 2. A normal scan under budget never reports exhaustion ----------------

func TestScan_NoMaxDurationNeverExhausted(t *testing.T) {
	ft := &slowFakeTransport{sleep: time.Millisecond}
	cfg := Config{Workers: 4, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true} // MaxDuration left at zero (unbounded)
	s := newMaxDurationTestScanner(t, cfg, ft)

	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stats.TimeBudgetExhausted {
		t.Fatal("did not expect TimeBudgetExhausted for a scan with MaxDuration unset")
	}
	if atomic.LoadInt32(&ft.calls) != 5 {
		t.Fatalf("expected all 5 planned jobs to complete when unbounded, got %d", atomic.LoadInt32(&ft.calls))
	}
}

func TestScan_MaxDurationWellAboveScanLengthNeverExhausted(t *testing.T) {
	ft := &slowFakeTransport{sleep: time.Millisecond}
	cfg := Config{Workers: 4, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxDuration: 30 * time.Second}
	s := newMaxDurationTestScanner(t, cfg, ft)

	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stats.TimeBudgetExhausted {
		t.Fatal("did not expect TimeBudgetExhausted when MaxDuration is far larger than the scan actually took")
	}
}

// --- 3. Graceful partial result when the deadline hits during crawl --------

func TestScan_MaxDurationGracefulOnCrawlTimeout(t *testing.T) {
	reg := detectors.NewRegistry(detectors.XSS{})
	cfg := Config{Workers: 2, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxDuration: 20 * time.Millisecond}
	s := New(cfg, reg)
	s.crawl = slowFakeCrawler{sleep: 80 * time.Millisecond} // sleeps well past the 20ms budget

	result, err := s.Scan(context.Background(), "http://fake.invalid")
	if err != nil {
		t.Fatalf("expected a crawl failure caused by the internal deadline to be reported as a graceful partial result, not an error: %v", err)
	}
	if !result.Stats.TimeBudgetExhausted {
		t.Fatal("expected Stats.TimeBudgetExhausted=true when the deadline elapses during crawl")
	}
	if result.SchemaVersion != "arfa.scan/v1" {
		t.Fatalf("expected a valid partial envelope with schema_version preserved, got %q", result.SchemaVersion)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected zero findings from a scan that never reached the job phase, got %d", len(result.Findings))
	}
}

// --- 4. External cancellation is never misreported as a time budget --------

func TestScan_ExternalCancellationNotReportedAsTimeBudget(t *testing.T) {
	reg := detectors.NewRegistry(detectors.XSS{})
	cfg := Config{Workers: 2, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxDuration: 5 * time.Second}
	s := New(cfg, reg)
	s.crawl = slowFakeCrawler{sleep: 50 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel almost immediately - well before either the crawl's own sleep
	// finishes or the 5s MaxDuration could ever elapse - so any observed
	// stoppage is unambiguously caused by the external cancellation.
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	result, err := s.Scan(ctx, "http://fake.invalid")
	if result.Stats.TimeBudgetExhausted {
		t.Fatal("external cancellation must never be reported as TimeBudgetExhausted")
	}
	if err == nil {
		t.Fatal("expected the real crawl error to be returned for external cancellation (not silently swallowed as a graceful timeout)")
	}
}

func TestScan_ExternalCancellationBeforeMaxDurationConfigured(t *testing.T) {
	// Even with no MaxDuration configured at all, an external cancellation
	// must not spuriously set TimeBudgetExhausted (it can't, since the
	// field is only ever touched when Config.MaxDuration > 0, but this
	// pins that behavior explicitly as a regression guard).
	reg := detectors.NewRegistry(detectors.XSS{})
	cfg := Config{Workers: 2, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := New(cfg, reg)
	s.crawl = slowFakeCrawler{sleep: 50 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before Scan even starts

	result, err := s.Scan(ctx, "http://fake.invalid")
	if result.Stats.TimeBudgetExhausted {
		t.Fatal("TimeBudgetExhausted must never be set when Config.MaxDuration is unset")
	}
	if err == nil {
		t.Fatal("expected the crawl error from an already-canceled ctx to be returned")
	}
}

// --- 5. No goroutine leak / deadlock on a MaxDuration cutoff ----------------

// TestScan_MaxDurationReturnsPromptlyWithNoInFlightProbes is the direct,
// non-NumGoroutine-based proof of graceful shutdown: Scan() must (a) return
// promptly once its internal deadline elapses, rather than hanging forever
// waiting on workers that never notice cancellation, and (b) have zero
// probes still in flight by the time it returns, proving every worker
// goroutine that started a probe also finished it and exited cleanly -
// wg.Wait() inside Scan() only completes once that is true.
func TestScan_MaxDurationReturnsPromptlyWithNoInFlightProbes(t *testing.T) {
	ft := &slowFakeTransport{sleep: 30 * time.Millisecond}
	cfg := Config{Workers: 3, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxDuration: 45 * time.Millisecond}
	s := newMaxDurationTestScanner(t, cfg, ft)

	type scanOutcome struct {
		result models.ScanResult
		err    error
	}
	done := make(chan scanOutcome, 1)
	go func() {
		r, e := s.Scan(context.Background(), "http://fake.invalid")
		done <- scanOutcome{result: r, err: e}
	}()

	var outcome scanOutcome
	select {
	case outcome = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Scan() did not return within a generous bound after MaxDuration elapsed - possible goroutine deadlock/leak")
	}

	if outcome.err != nil {
		t.Fatalf("unexpected error: %v", outcome.err)
	}
	if !outcome.result.Stats.TimeBudgetExhausted {
		t.Fatal("expected TimeBudgetExhausted=true for this timing configuration")
	}
	if active := atomic.LoadInt32(&ft.active); active != 0 {
		t.Fatalf("expected zero in-flight probes once Scan() returned (workers must have fully exited), got %d still active", active)
	}
}

// --- 6. Existing cancellation semantics remain intact with MaxDuration set -

// TestScan_ExistingCancellationStillWorksAlongsideMaxDuration confirms
// TD #7 is additive: the pre-existing "caller cancels ctx" path is
// unaffected by configuring an (uninvolved, much larger) MaxDuration.
func TestScan_ExistingCancellationStillWorksAlongsideMaxDuration(t *testing.T) {
	ft := &slowFakeTransport{sleep: 200 * time.Millisecond}
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true, MaxDuration: time.Hour}
	s := newMaxDurationTestScanner(t, cfg, ft)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	result, err := s.Scan(ctx, "http://fake.invalid")
	if err != nil {
		t.Fatalf("unexpected error from external ctx cancellation: %v", err)
	}
	if result.Stats.TimeBudgetExhausted {
		t.Fatal("expected TimeBudgetExhausted=false: the caller's own ctx timeout fired first, not the (much larger) MaxDuration")
	}
	if calls := atomic.LoadInt32(&ft.calls); calls >= 5 {
		t.Fatalf("expected the caller's short ctx timeout to still cut the scan short, got all %d jobs run", calls)
	}
}
