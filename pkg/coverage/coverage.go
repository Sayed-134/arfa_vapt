// Package coverage tracks, per endpoint × parameter × vulnerability-class
// combination, how much testing has actually happened and how it resolved.
// It is the deterministic bookkeeping the Milestone 2 planner (pkg/planner)
// reads from to answer "what should be tested next, and why" - the tracker
// itself makes no decisions and issues no probes.
package coverage

import (
	"sort"
	"sync"

	"arfa/pkg/models"
)

// Key identifies one cell in the coverage matrix.
type Key struct {
	Endpoint  string
	Parameter string
	Category  string
}

// rank defines the only direction a cell's state is ever allowed to move:
// a later, weaker observation must never erase a stronger one already
// recorded for the same key (e.g. one payload confirming a real
// vulnerability must not be "downgraded" back to Attempted just because a
// different payload against the same endpoint/parameter/category came back
// inconclusive). Verified is the strongest signal; NotAttempted the
// weakest.
var rank = map[models.CoverageState]int{
	models.CoverageNotAttempted: 0,
	models.CoverageAttempted:    1,
	models.CoverageFailed:       2,
	models.CoverageInconclusive: 3,
	models.CoverageVerified:     4,
}

// Tracker is safe for concurrent use by multiple scan workers.
type Tracker struct {
	mu sync.Mutex
	m  map[Key]models.CoverageState
}

// New returns an empty Tracker.
func New() *Tracker {
	return &Tracker{m: map[Key]models.CoverageState{}}
}

// Seed registers a key as NotAttempted if it is not already present. Call
// this for every endpoint × parameter × category combination the scheduler
// is aware of *before* any probes run, so the final coverage snapshot shows
// what was never tested at all - not just what happened to produce a
// finding. Seeding an already-present key is a no-op (it never downgrades
// a key back to NotAttempted).
func (t *Tracker) Seed(key Key) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.m[key]; !ok {
		t.m[key] = models.CoverageNotAttempted
	}
}

// Mark records an observation for key. If the new state is not stronger
// than what's already recorded (per rank above), the existing state is
// left unchanged - this makes Mark safe to call from concurrent workers in
// any order and still converge on a deterministic result: the strongest
// observation for each key always wins, regardless of goroutine
// scheduling.
func (t *Tracker) Mark(key Key, state models.CoverageState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.m[key]; !ok || rank[state] > rank[current] {
		t.m[key] = state
	}
}

// Snapshot returns every tracked cell as a stably-sorted slice (by
// Endpoint, then Parameter, then Category) so JSON output and planner
// input are deterministic across runs, not dependent on Go map iteration
// order.
func (t *Tracker) Snapshot() []models.CoverageEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]models.CoverageEntry, 0, len(t.m))
	for k, state := range t.m {
		out = append(out, models.CoverageEntry{Endpoint: k.Endpoint, Parameter: k.Parameter, Category: k.Category, State: state})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		if out[i].Parameter != out[j].Parameter {
			return out[i].Parameter < out[j].Parameter
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// FromVerificationStatus maps a Finding's full-fidelity verification status
// string down to the coarser CoverageState vocabulary. Unknown/empty
// statuses map to Attempted (we know a probe happened; we don't know more
// than that), never silently to NotAttempted or Verified.
func FromVerificationStatus(status string) models.CoverageState {
	switch status {
	case "CONFIRMED":
		return models.CoverageVerified
	case "FALSE_POSITIVE":
		return models.CoverageFailed
	case "LIKELY", "PROBABLE", "POTENTIAL", "INCONCLUSIVE", "UNVERIFIED":
		return models.CoverageInconclusive
	default:
		return models.CoverageAttempted
	}
}
