package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"arfa/pkg/adaptive"
	"arfa/pkg/models"
)

// TD #8 — Global/cancellable rate limiter policy.
//
// pkg/ratelimiter/limiter_test.go covers the Limiter itself (global
// pacing, cancellation, Feedback semantics). These tests cover the other
// required-test item that is specifically pkg/scanner's responsibility:
// rawProbe() must check s.lim.Wait(ctx)'s error and abort the probe -
// never sending an HTTP request - before any request is issued, and must
// propagate the error unchanged.

// TestRawProbe_AlreadyCanceledContextSkipsHTTPRequest is the direct
// regression test for the previously-ignored `_ = s.lim.Wait(ctx)`: a
// caller whose ctx is already canceled must never reach s.http.Do at all.
func TestRawProbe_AlreadyCanceledContextSkipsHTTPRequest(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)
	ft := &fakeTransport{body: "ok", status: 200}
	s.http = ft

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ctrl := adaptive.New(1)
	pr := s.rawProbe(ctx, ctrl, models.Endpoint{URL: "http://fake.invalid/x", Method: "GET"}, "q", "v", nil)

	if pr.Err == nil {
		t.Fatal("expected a non-nil ProbeResult.Err when ctx is already canceled")
	}
	if !errors.Is(pr.Err, context.Canceled) {
		t.Fatalf("expected context.Canceled propagated unchanged, got %v", pr.Err)
	}
	if ft.calls != 0 {
		t.Fatalf("expected zero HTTP calls when the rate limiter's Wait is canceled before the request, got %d", ft.calls)
	}
}

// TestRawProbe_CancellationDuringWaitSkipsHTTPRequest confirms the same
// holds when cancellation happens *during* the limiter's Wait, not only
// when ctx is already done up front.
func TestRawProbe_CancellationDuringWaitSkipsHTTPRequest(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true} // ~1s limiter interval
	s := newTestScanner(t, cfg)
	ft := &fakeTransport{body: "ok", status: 200}
	s.http = ft

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	ctrl := adaptive.New(1)
	pr := s.rawProbe(ctx, ctrl, models.Endpoint{URL: "http://fake.invalid/x", Method: "GET"}, "q", "v", nil)

	if !errors.Is(pr.Err, context.Canceled) {
		t.Fatalf("expected context.Canceled propagated unchanged, got %v", pr.Err)
	}
	if ft.calls != 0 {
		t.Fatalf("expected zero HTTP calls when canceled mid-Wait, got %d", ft.calls)
	}
}

// TestRawProbe_CancellationDoesNotInvokeOnDone confirms Stats.Requests
// accounting (driven by the onDone callback in the real scan loop) is
// unaffected: a probe that never reached the network must not be counted
// as one.
func TestRawProbe_CancellationDoesNotInvokeOnDone(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)
	ft := &fakeTransport{body: "ok", status: 200}
	s.http = ft

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ctrl := adaptive.New(1)
	onDoneCalls := 0
	_ = s.rawProbe(ctx, ctrl, models.Endpoint{URL: "http://fake.invalid/x", Method: "GET"}, "q", "v", func(models.ProbeResult) {
		onDoneCalls++
	})

	if onDoneCalls != 0 {
		t.Fatalf("expected onDone to not be invoked when no HTTP request was sent, got %d calls", onDoneCalls)
	}
}

// TestRawProbe_UncanceledContextStillSendsRequest is the regression guard
// that TD #8 does not accidentally suppress ordinary, non-canceled probes:
// existing behavior (request sent, onDone invoked) must be unchanged.
func TestRawProbe_UncanceledContextStillSendsRequest(t *testing.T) {
	cfg := Config{Workers: 1, Rate: 1000, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)
	ft := &fakeTransport{body: "ok", status: 200}
	s.http = ft

	ctrl := adaptive.New(1)
	onDoneCalls := 0
	pr := s.rawProbe(context.Background(), ctrl, models.Endpoint{URL: "http://fake.invalid/x", Method: "GET"}, "q", "v", func(models.ProbeResult) {
		onDoneCalls++
	})

	if pr.Err != nil {
		t.Fatalf("unexpected error: %v", pr.Err)
	}
	if ft.calls != 1 {
		t.Fatalf("expected exactly 1 HTTP call, got %d", ft.calls)
	}
	if onDoneCalls != 1 {
		t.Fatalf("expected onDone to be invoked exactly once, got %d", onDoneCalls)
	}
}

// TestScan_InitialAndVerificationProbesShareOneLimiter is the scanner-level
// counterpart to required-test item 12: initial detect probes and
// verification (repeat/control) probes for the same scan must go through
// the same *ratelimiter.Limiter instance (s.lim) - not a per-phase or
// per-worker limiter - so global pacing covers the whole scan, not just
// the initial detection pass.
func TestScan_InitialAndVerificationProbesShareOneLimiter(t *testing.T) {
	cfg := Config{Workers: 2, Rate: 200, Timeout: 2 * time.Second, Mode: Quick, MaxPages: 5, SkipPreflight: true}
	s := newTestScanner(t, cfg)

	ft := &fakeTransport{body: "<html><body><xsstestmarker></body></html>", status: 200}
	fc := fakeCrawler{eps: []models.Endpoint{{URL: "http://fake.invalid/page", Method: "GET", Parameters: []string{"q"}}}, pages: 1}
	s.crawl = fc
	s.http = ft

	limBefore := s.lim
	if _, err := s.Scan(context.Background(), "http://fake.invalid"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.lim != limBefore {
		t.Fatal("expected the Scanner's single *ratelimiter.Limiter to remain the same instance across a scan (initial + verification probes)")
	}
}
