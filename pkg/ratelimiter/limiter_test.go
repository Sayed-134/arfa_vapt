package ratelimiter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TD #8 — Global/cancellable rate limiter policy.
//
// These tests cover the Required Tests list in
// PHASE_4_TD_SPECS.md §TD #8, scoped to what pkg/ratelimiter itself is
// responsible for (global pacing and cancellation). The scanner-level
// integration items (rawProbe respecting Wait's error, verification/
// initial probes sharing one limiter) are covered separately in
// pkg/scanner.

// --- 1 & 2. One shared limiter; global pacing across concurrent callers ---

// TestWait_GlobalPacingAcrossConcurrentCallers is the direct regression
// test for the "independent per-caller delay, not real global serialized
// pacing" gap: N goroutines calling Wait() concurrently on the same
// Limiter must still be paced at one slot per interval, not all released
// together after a single interval.
func TestWait_GlobalPacingAcrossConcurrentCallers(t *testing.T) {
	l := New(1000) // ~1ms interval; small enough to keep the test fast
	interval := l.Interval()

	const n = 8
	var wg sync.WaitGroup
	start := time.Now()
	times := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := l.Wait(context.Background()); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			times[i] = time.Since(start)
		}(i)
	}
	wg.Wait()

	// With true global pacing, the n-th slot to fire cannot be released
	// before roughly (n-1) full intervals have elapsed relative to the
	// first - if pacing were merely per-caller (all callers reading the
	// same interval and sleeping independently), all n could complete in
	// roughly one interval instead.
	sortDurations(times)
	minSpan := time.Duration(n-1) * interval / 2 // generous tolerance
	span := times[n-1] - times[0]
	if span < minSpan {
		t.Fatalf("expected concurrent callers to be globally paced across roughly %d intervals (>= %v), got a span of only %v (times=%v)", n-1, minSpan, span, times)
	}
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j-1] > d[j]; j-- {
			d[j-1], d[j] = d[j], d[j-1]
		}
	}
}

// --- 3. Cancellation during Wait -------------------------------------------

func TestWait_CancellationReturnsContextCanceled(t *testing.T) {
	l := New(1) // ~1s interval, long enough that cancellation fires first
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := l.Wait(ctx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled propagated unchanged, got %v", err)
	}
}

// --- 4. Deadline during Wait ------------------------------------------------

func TestWait_DeadlineReturnsDeadlineExceeded(t *testing.T) {
	l := New(1) // ~1s interval, long enough that the deadline fires first
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := l.Wait(ctx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded propagated unchanged, got %v", err)
	}
}

// TestWait_AlreadyCanceledContextReturnsImmediately confirms a caller whose
// ctx is already done before Wait is even invoked is rejected immediately,
// without reserving a slot or blocking at all.
func TestWait_AlreadyCanceledContextReturnsImmediately(t *testing.T) {
	l := New(1) // ~1s interval
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := l.Wait(ctx)
	elapsed := time.Since(start)

	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("expected an already-canceled ctx to return immediately, took %v", elapsed)
	}
}

// --- 5 & 9. Feedback affects new waits only; no retroactive burst ---------

// TestFeedback_DoesNotAffectAlreadyReservedWait confirms the documented
// semantics: once Wait has reserved a slot (and is sleeping toward it), a
// concurrent Feedback() call that changes the interval must not alter that
// already-reserved wait's duration.
func TestFeedback_DoesNotAffectAlreadyReservedWait(t *testing.T) {
	l := New(20) // 50ms interval
	// Prime l.next so the second Wait's slot is a known, non-trivial delay.
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error priming the limiter: %v", err)
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- l.Wait(context.Background())
	}()

	// Give the goroutine time to reserve its slot before mutating the
	// interval underneath it.
	time.Sleep(5 * time.Millisecond)
	l.Feedback(429, nil) // doubles the interval for *future* reservations

	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed := time.Since(start)

	// The in-flight wait was reserved against the original ~50ms interval,
	// not the doubled ~100ms one - it must complete close to the original
	// interval, not the doubled one.
	if elapsed > 80*time.Millisecond {
		t.Fatalf("expected the already-reserved wait to keep its original ~50ms duration unaffected by the later Feedback() call, took %v", elapsed)
	}
}

// TestFeedback_NewWaitsUseUpdatedInterval confirms the other half of the
// same contract: a Wait that reserves its slot *after* Feedback() changed
// the interval must use the new interval, so degrading the rate is not
// silently ignored either.
func TestFeedback_NewWaitsUseUpdatedInterval(t *testing.T) {
	l := New(100) // 10ms interval
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error priming the limiter: %v", err)
	}
	l.Feedback(429, nil) // interval -> 20ms
	l.Feedback(429, nil) // interval -> 40ms
	want := l.Interval()

	start := time.Now()
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < want/2 {
		t.Fatalf("expected the new wait to be paced by the updated interval (~%v), completed in only %v", want, elapsed)
	}
}

// --- 6. Concurrent Wait + Feedback, no race (run with -race) --------------

func TestConcurrentWaitAndFeedbackNoRace(t *testing.T) {
	l := New(2000) // ~0.5ms interval, keeps the test fast
	var wg sync.WaitGroup

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Wait(context.Background())
		}()
	}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				l.Feedback(429, nil)
			} else {
				l.Feedback(200, nil)
			}
		}(i)
	}
	wg.Wait()
}

// --- 7. Initial rate policy is deterministic --------------------------------

func TestNew_InitialIntervalIsDeterministic(t *testing.T) {
	a := New(10)
	b := New(10)
	if a.Interval() != b.Interval() {
		t.Fatalf("expected the same reqPerSec to always produce the same initial interval, got %v and %v", a.Interval(), b.Interval())
	}
}

// --- 11. No goroutine/timer leak on cancellation ---------------------------

// TestWait_TimerStoppedOnCancellation is a direct (non-runtime.NumGoroutine)
// proof that a canceled Wait does not leave its timer's channel pending
// forever: defer t.Stop() runs on every return path, and this test simply
// exercises the cancellation path many times without hanging or leaking -
// a leaking timer would eventually manifest as growing memory/goroutines
// under `go test -race` and CI's leak detectors, but the direct assertion
// here is that repeated cancel-during-Wait calls complete promptly.
func TestWait_TimerStoppedOnCancellation(t *testing.T) {
	l := New(1) // ~1s interval, so every call below is cancelled well before firing
	var completed int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
			defer cancel()
			_ = l.Wait(ctx)
			atomic.AddInt32(&completed, 1)
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("expected all canceled Wait() calls to return promptly - possible timer/goroutine leak")
	}
	if atomic.LoadInt32(&completed) != 20 {
		t.Fatalf("expected all 20 calls to complete, got %d", completed)
	}
}
