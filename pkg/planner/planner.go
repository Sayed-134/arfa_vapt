// Package planner answers one narrow question, deterministically and from
// coverage data alone: "what should ARFA test next, and why?"
//
// This is the Milestone 2 *foundation* only, per the project's master
// context (§10, §14): a pure function over a coverage snapshot, with no
// LLM call, no autonomous execution, and no side effects. It does not
// decide anything on its own and nothing in this codebase currently
// executes a returned Action automatically - a future bounded-agent-loop
// milestone is expected to consume this output, not this package to grow
// into that loop.
package planner

import (
	"sort"

	"arfa/pkg/models"
)

// DefaultMaxActions is used when Plan is called with maxActions <= 0, so
// the planner is bounded even if a caller forgets to set a limit.
const DefaultMaxActions = 20

// reasons for each coverage state Plan considers actionable. Kept as a
// lookup so the wording is defined in exactly one place.
var reasons = map[models.CoverageState]string{
	models.CoverageInconclusive: "previously tested but the verification engine could not confirm or refute the result; a repeat/control probe may settle it",
	models.CoverageNotAttempted: "no detector has tested this endpoint/parameter for this vulnerability class yet",
}

// priority for each actionable state - lower runs first. Inconclusive
// outranks NotAttempted: resolving an ambiguous result already has partial
// signal behind it and costs at most two extra probes (see
// pkg/verification.Verify), while a fresh NotAttempted cell is a larger,
// less-targeted unit of work.
var priority = map[models.CoverageState]int{
	models.CoverageInconclusive: 0,
	models.CoverageNotAttempted: 1,
}

// Plan derives up to maxActions recommended next tests from a coverage
// snapshot. Only CoverageInconclusive and CoverageNotAttempted cells are
// ever actionable - CoverageVerified and CoverageFailed are resolved
// outcomes and are never suggested again. Output is deterministic: stable
// priority ordering, then alphabetical (endpoint, parameter, category) as a
// tiebreak, every time, for the same input - no randomness, no clock, no
// external call.
func Plan(coverage []models.CoverageEntry, maxActions int) []models.NextAction {
	if maxActions <= 0 {
		maxActions = DefaultMaxActions
	}

	candidates := make([]models.NextAction, 0, len(coverage))
	for _, c := range coverage {
		reason, ok := reasons[c.State]
		if !ok {
			continue // Verified / Failed / any future state: resolved, not actionable
		}
		candidates = append(candidates, models.NextAction{
			Endpoint:  c.Endpoint,
			Parameter: c.Parameter,
			Category:  c.Category,
			Reason:    reason,
			Priority:  priority[c.State],
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		if candidates[i].Endpoint != candidates[j].Endpoint {
			return candidates[i].Endpoint < candidates[j].Endpoint
		}
		if candidates[i].Parameter != candidates[j].Parameter {
			return candidates[i].Parameter < candidates[j].Parameter
		}
		return candidates[i].Category < candidates[j].Category
	})

	if len(candidates) > maxActions {
		candidates = candidates[:maxActions]
	}
	return candidates
}
