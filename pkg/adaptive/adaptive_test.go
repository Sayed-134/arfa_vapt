package adaptive

import "testing"

func TestAcquireReleaseRespectsCeiling(t *testing.T) {
	c := New(2)
	c.Acquire()
	c.Acquire()
	done := make(chan struct{})
	go func() {
		c.Acquire()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("acquired a third permit while ceiling was 2 and both were held")
	default:
	}
	c.Release()
	<-done
	c.Release()
	c.Release()
}

func TestReportShrinksAndGrowsBudget(t *testing.T) {
	c := New(4)
	for i := 0; i < 20; i++ {
		c.Report(true)
	}
	if b := c.Budget(); b >= 4 {
		t.Fatalf("expected budget to shrink under sustained errors, got %d", b)
	}
	for i := 0; i < 100; i++ {
		c.Report(false)
	}
	if b := c.Budget(); b != 4 {
		t.Fatalf("expected budget to recover to ceiling under sustained success, got %d", b)
	}
}

// TestShrinkWhileFullyInFlightIsNotLost exercises the case the pendingSkip
// design exists for: a shrink is requested while every permit is currently
// held (channel empty), so there is nothing to drain immediately. The
// shrink must still be honored exactly once, via the next Release call.
func TestShrinkWhileFullyInFlightIsNotLost(t *testing.T) {
	c := New(2)
	c.Acquire()
	c.Acquire()
	for i := 0; i < 20; i++ {
		c.Report(true)
	}
	if b := c.Budget(); b != 1 {
		t.Fatalf("expected budget 1, got %d", b)
	}
	c.Release()
	c.Release()

	c.Acquire()
	done := make(chan struct{})
	go func() {
		c.Acquire()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("acquired a second permit after a realized shrink to budget 1")
	default:
	}
	c.Release()
	<-done
	c.Release()
}
