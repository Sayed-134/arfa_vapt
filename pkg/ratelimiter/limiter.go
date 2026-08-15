package ratelimiter

import (
	"context"
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	min, max time.Duration
}

func New(reqPerSec float64) *Limiter {
	if reqPerSec < 0.2 {
		reqPerSec = 0.2
	}
	i := time.Duration(float64(time.Second) / reqPerSec)
	return &Limiter{interval: i, min: time.Millisecond * 10, max: time.Second * 5}
}
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	d := l.interval
	l.mu.Unlock()
	t := time.NewTimer(d)
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
