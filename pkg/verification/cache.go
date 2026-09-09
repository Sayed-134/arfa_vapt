package verification

import "sync"

// Cache stores Verify Results for the duration of one scan, keyed by
// CacheKey, so that verifying an effectively identical candidate a second
// time - same vulnerability category, endpoint, parameter and exact
// payload value - reuses the first Result instead of issuing another
// repeat+control probe pair. This exists specifically to avoid the
// uncontrolled request amplification ARCHITECTURE.md §11 warns against; it
// never causes an additional request on its own, only prevents duplicate
// ones for identical work. Verify is deterministic given identical inputs
// against an unchanged target, so reusing a cached Result does not weaken
// verification - it skips redoing verification the engine already did.
//
// Cache is safe for concurrent use by multiple scan workers.
type Cache struct {
	mu    sync.Mutex
	m     map[string]Result
	calls map[string]*call // keys currently being computed by GetOrCompute
}

// call tracks one in-flight GetOrCompute computation for a single key, so
// concurrent callers for that same key can wait on it instead of starting
// their own redundant computation.
type call struct {
	done   chan struct{}
	result Result
}

// NewCache returns an empty, ready-to-use Cache. A fresh Cache should be
// created per scan (never reused across scans/targets), since a cached
// Result reflects the target's state at the time it was captured.
func NewCache() *Cache {
	return &Cache{m: make(map[string]Result), calls: make(map[string]*call)}
}

// CacheKey builds the cache key for one verification candidate. Two
// candidates only ever share a key if they are indistinguishable from
// verification's point of view: same vulnerability category, same
// endpoint, same parameter, same exact payload value sent on the wire.
func CacheKey(category, endpoint, parameter, payloadValue string) string {
	return category + "|" + endpoint + "|" + parameter + "|" + payloadValue
}

// Get returns the cached Result for key, if present.
func (c *Cache) Get(key string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[key]
	return r, ok
}

// Set stores a Result under key, overwriting any prior entry. Verify
// results are deterministic given identical inputs, so if two callers race
// to compute and store the same key, last-write-wins is safe: both
// computed results are equivalent. Prefer GetOrCompute over a manual
// Get-then-Set pair: that pattern is not atomic and lets two concurrent
// workers both observe a cache miss and both run compute(), which is
// exactly the duplicate-verification race GetOrCompute exists to close.
func (c *Cache) Set(key string, r Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = r
}

// GetOrCompute returns the cached Result for key if present. Otherwise it
// runs compute() to produce one - exactly once per key, even when many
// callers request the same key concurrently - caches it, and returns it to
// every waiter. Callers for different keys never block on each other:
// compute() always runs without holding the Cache's lock, so unrelated
// keys proceed fully in parallel while identical keys are single-flighted
// onto one execution of compute(). This is the fix for the Get/Set race:
// a plain "Get, then on miss compute and Set" is not atomic, so two
// workers hitting the same key at nearly the same time could both observe
// a miss and both run compute() - defeating the cache's purpose of
// avoiding duplicate repeat+control verification probes.
//
// compute() must itself already respect context cancellation, timeouts and
// rate limits (Verify does, via its bounded retry); GetOrCompute adds no
// additional waiting beyond what compute() itself takes to return.
func (c *Cache) GetOrCompute(key string, compute func() Result) Result {
	c.mu.Lock()
	if r, ok := c.m[key]; ok {
		c.mu.Unlock()
		return r
	}
	if inFlight, ok := c.calls[key]; ok {
		c.mu.Unlock()
		<-inFlight.done
		return inFlight.result
	}
	cl := &call{done: make(chan struct{})}
	c.calls[key] = cl
	c.mu.Unlock()

	result := compute()

	c.mu.Lock()
	cl.result = result
	c.m[key] = result
	delete(c.calls, key)
	c.mu.Unlock()
	close(cl.done)

	return result
}

// Len reports how many entries are currently cached.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
