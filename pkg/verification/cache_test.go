package verification

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheGetSet(t *testing.T) {
	c := NewCache()
	key := CacheKey("XSS", "http://x/a", "q", "<script>")

	if _, ok := c.Get(key); ok {
		t.Fatal("expected empty cache to have no entry")
	}

	want := Result{Status: Confirmed, Detail: "d", Confidence: ConfidenceHigh}
	c.Set(key, want)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cached entry to be present after Set")
	}
	if got.Status != want.Status || got.Confidence != want.Confidence {
		t.Fatalf("expected cached Result to round-trip unchanged, got %+v", got)
	}
	if c.Len() != 1 {
		t.Fatalf("expected Len()=1, got %d", c.Len())
	}
}

func TestCacheKeyDistinguishesCandidates(t *testing.T) {
	base := CacheKey("XSS", "http://x/a", "q", "<script>")
	variants := []string{
		CacheKey("SQLi", "http://x/a", "q", "<script>"),      // different category
		CacheKey("XSS", "http://x/b", "q", "<script>"),       // different endpoint
		CacheKey("XSS", "http://x/a", "id", "<script>"),      // different parameter
		CacheKey("XSS", "http://x/a", "q", "<script>alert>"), // different payload value
	}
	for _, v := range variants {
		if v == base {
			t.Fatalf("expected distinct candidates to produce distinct cache keys, got collision for %q", v)
		}
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := NewCache()
	key := CacheKey("XSS", "http://x/a", "q", "<script>")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Set(key, Result{Status: Confirmed})
			c.Get(key)
		}()
	}
	wg.Wait()
	if c.Len() != 1 {
		t.Fatalf("expected exactly 1 entry after concurrent writes to the same key, got %d", c.Len())
	}
}

// TestCacheGetOrCompute_SingleFlightSameKey is the regression test for the
// concurrent cache-miss race: a plain Get-then-Set is not atomic, so many
// workers hitting the same key at once could each observe a miss and each
// run compute() - defeating the point of the cache. This test forces that
// exact race deterministically (via a gate the first caller blocks on)
// rather than hoping timing exposes it, and asserts compute() still only
// ran once.
func TestCacheGetOrCompute_SingleFlightSameKey(t *testing.T) {
	c := NewCache()
	key := CacheKey("XSS", "http://x/a", "q", "<script>")

	var calls int32
	entered := make(chan struct{})
	release := make(chan struct{})

	compute := func() Result {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(entered)
			<-release // hold the one-and-only computation open
		}
		return Result{Status: Confirmed, Detail: "computed once"}
	}

	const n = 20
	results := make([]Result, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = c.GetOrCompute(key, compute)
		}(i)
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the single in-flight computation to start")
	}
	// Give the other n-1 goroutines time to arrive at GetOrCompute and
	// join the in-flight call instead of starting their own computation,
	// before releasing the one computation that's allowed to run.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected compute() to run exactly once for %d concurrent callers on the same key, ran %d times", n, got)
	}
	for i, r := range results {
		if r.Status != Confirmed || r.Detail != "computed once" {
			t.Fatalf("caller %d got a different Result than the single computed one: %+v", i, r)
		}
	}
	if c.Len() != 1 {
		t.Fatalf("expected exactly 1 cached entry after the single computation completed, got %d", c.Len())
	}
}

// TestCacheGetOrCompute_DifferentKeysRunConcurrently guards against an
// overly broad fix: single-flighting identical keys must not accidentally
// serialize distinct keys onto one global lock held for the duration of
// compute(). Both computations below must be able to enter before either
// is allowed to finish, or this test times out.
func TestCacheGetOrCompute_DifferentKeysRunConcurrently(t *testing.T) {
	c := NewCache()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})

	compute := func() Result {
		entered <- struct{}{}
		<-release
		return Result{Status: Confirmed}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.GetOrCompute(CacheKey("XSS", "http://x/a", "q", "v1"), compute)
	}()
	go func() {
		defer wg.Done()
		c.GetOrCompute(CacheKey("SQLi", "http://x/b", "id", "v2"), compute)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("expected both distinct-key computations to be able to run concurrently, but only one entered")
		}
	}
	close(release)
	wg.Wait()

	if c.Len() != 2 {
		t.Fatalf("expected 2 independent cached entries, got %d", c.Len())
	}
}

// TestCacheGetOrCompute_CachedResultServedWithoutRecomputing confirms the
// ordinary (non-racing) path: once a key is resolved, later callers get the
// cached Result and never invoke compute() again.
func TestCacheGetOrCompute_CachedResultServedWithoutRecomputing(t *testing.T) {
	c := NewCache()
	key := CacheKey("XSS", "http://x/a", "q", "<script>")
	var calls int32
	compute := func() Result {
		atomic.AddInt32(&calls, 1)
		return Result{Status: Confirmed}
	}

	first := c.GetOrCompute(key, compute)
	second := c.GetOrCompute(key, compute)

	if first.Status != Confirmed || second.Status != Confirmed {
		t.Fatalf("expected both calls to return Confirmed, got %+v and %+v", first, second)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected compute() to run once and the second call to be served from cache, ran %d times", got)
	}
}
