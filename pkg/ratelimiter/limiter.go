package ratelimiter

import (
	"context"
	"sync"
	"time"
)

// TD #8 — Global/cancellable rate limiter policy.
//
// A Limiter is shared by every worker/probe in one Scan (see
// pkg/scanner.Scanner.lim) - there is exactly one Limiter per scan, never
// one per worker or per detector. Wait now reserves a global "next slot"
// time under the same lock used by Feedback, instead of each caller
// independently sleeping for whatever l.interval happened to be when it
// read it. This is what makes pacing actually global: N concurrent callers
// reserve N distinct, interval-spaced slots rather than all sleeping the
// same duration and firing together.
//
// Each reservation adds the *current* l.interval - read under the same
// lock, at the moment that caller reserves its slot - on top of the
// previously-reserved slot. A wait already in progress (its slot already
// reserved) is therefore never altered by a later Feedback() call, because
// its own wait duration was fixed the instant it reserved its slot; a wait
// that reserves its slot only after Feedback() ran picks up the new
// interval, since it reads l.interval fresh at that later time. This is
// exactly the spec's "Feedback affects new waits only, already-started
// waiters keep their computed delay, no burst" requirement.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	min, max time.Duration
	// next is the fire time already reserved for the most recently
	// admitted caller. Zero value (time.Time{}) means no slot has been
	// reserved yet.
	next time.Time
}

func New(reqPerSec float64) *Limiter {
	if reqPerSec < 0.2 {
		reqPerSec = 0.2
	}
	i := time.Duration(float64(time.Second) / reqPerSec)
	return &Limiter{interval: i, min: time.Millisecond * 10, max: time.Second * 5}
}

// Wait blocks until this caller's globally-reserved slot arrives, or ctx is
// done, whichever happens first. It always respects ctx: a caller whose ctx
// is already canceled/expired when Wait is invoked returns immediately
// with ctx.Err(), without reserving a slot at all, and a caller already
// waiting on its reserved slot returns the instant ctx is canceled - never
// after. ctx.Err() (context.Canceled or context.DeadlineExceeded) is
// returned unchanged, never wrapped or reinterpreted, so callers can
// propagate or inspect it directly.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	now := time.Now()
	base := l.next
	if base.Before(now) {
		base = now
	}
	fire := base.Add(l.interval)
	l.next = fire
	l.mu.Unlock()

	wait := fire.Sub(now)
	if wait <= 0 {
		return ctx.Err()
	}

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func (l *Limiter) Feedback(status int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if status == 429 || status == 403 || err != nil {
		l.interval *= 2
		if l.interval > l.max {
			l.interval = l.max
		}
		return
	}
	if status >= 200 && status < 500 {
		l.interval *= 9 / 10
		if l.interval < l.min {
			l.interval = l.min
		}
	}
}
func (l *Limiter) Interval() time.Duration { l.mu.Lock(); defer l.mu.Unlock(); return l.interval }
