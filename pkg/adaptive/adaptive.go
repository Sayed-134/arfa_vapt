// Package adaptive provides a lightweight concurrency controller that lets
// the scanner respond to error/throttle signals (429, 403, timeouts,
// connection failures) by shrinking effective concurrency, and grow it back
// once the target looks healthy again.
//
// It deliberately does NOT stop or start goroutines mid-scan — the worker
// pool size from Config.Workers is still the hard ceiling. Instead it hands
// out a bounded number of "permits"; when the error rate rises, permits are
// pulled out of circulation so fewer workers are doing real work at once
// even though the goroutines themselves are still alive and blocked waiting
// for a permit. This is a first step toward the full CPU/RAM/latency-aware
// scheduler described in the project's adaptive-resource-management goal;
// it currently reacts to error rate only.
package adaptive

import "sync"

// Controller hands out concurrency permits and adjusts how many are in
// circulation based on a rolling window of recent request outcomes.
type Controller struct {
	mu          sync.Mutex
	total       int
	budget      int
	pendingSkip int // outstanding "IOUs": the next N Release calls withhold their token instead of returning it, so a shrink requested while every permit is in-flight is never lost
	window      []bool
	windowSize  int
	permits     chan struct{}
}

// New creates a Controller with the given ceiling (normally cfg.Workers).
// All permits start available, so behavior is unchanged from a fixed pool
// until enough signal accumulates to justify shrinking it.
func New(workers int) *Controller {
	if workers < 1 {
		workers = 1
	}
	c := &Controller{total: workers, budget: workers, windowSize: 20, permits: make(chan struct{}, workers)}
	for i := 0; i < workers; i++ {
		c.permits <- struct{}{}
	}
	return c
}

// Acquire blocks until a concurrency permit is available.
func (c *Controller) Acquire() { <-c.permits }

// Release returns a permit, unless a shrink is still owed (pendingSkip),
// in which case this call pays down that debt instead and the permit is
// permanently removed from circulation. Every Acquire must be paired with
// exactly one Release, normally via defer at the call site.
func (c *Controller) Release() {
	c.mu.Lock()
	if c.pendingSkip > 0 {
		c.pendingSkip--
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.permits <- struct{}{}
}

// Report feeds a single request outcome into the rolling window. throttled
// should be true for a 429, 403, timeout, or connection error, and false
// for a normal completed request (regardless of status code otherwise).
func (c *Controller) Report(throttled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.window = append(c.window, throttled)
	if len(c.window) > c.windowSize {
		c.window = c.window[1:]
	}
	if len(c.window) < c.windowSize/2 {
		return // not enough signal yet to make a decision
	}

	errCount := 0
	for _, v := range c.window {
		if v {
			errCount++
		}
	}
	rate := float64(errCount) / float64(len(c.window))

	switch {
	case rate > 0.3 && c.budget > 1:
		// Shrink by one. We do not try to drain a token from the channel
		// here — under load every token may currently be held by an
		// in-flight probe, so draining could silently fail. Instead we
		// record an IOU that the next Release() call honors, guaranteeing
		// the shrink is eventually realized exactly once.
		c.budget--
		c.pendingSkip++
	case rate < 0.05 && c.budget < c.total:
		// Grow by one. First cancel a still-outstanding shrink IOU if one
		// exists (cheapest: no channel token was ever actually removed for
		// it, so nothing needs to be added back). Only if no IOU remains do
		// we inject a fresh token — meaning an earlier shrink was already
		// fully realized and we're now genuinely restoring capacity.
		c.budget++
		if c.pendingSkip > 0 {
			c.pendingSkip--
		} else {
			select {
			case c.permits <- struct{}{}:
			default:
				// Should not happen if the invariant above holds, but
				// never block or panic from inside Report.
			}
		}
	}
}

// Budget returns the current concurrency budget, for logging/reporting.
func (c *Controller) Budget() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.budget
}
