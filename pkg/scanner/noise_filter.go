package scanner

import "strings"

// TD #5 — Fallback Parameter Noise (see PHASE_4_TD_SPECS.md).
//
// knownNoiseParameters is the explicit, fixed list of crawler-discovered
// parameter names that are filtered out before they become scan work.
// These are common tracking/cache-busting parameters that do not
// represent meaningful security input surface.
//
// This is deliberately NOT a heuristic: nothing here infers noise from a
// parameter's shape (numeric, timestamp-like, random-looking, short/long,
// or varying between requests). Only an exact name match against this
// fixed list is ever filtered; every other parameter is conservatively
// preserved, per the spec's "Conservative fallback" requirement.
//
// This list has no relationship to effectiveParams' separate GET fallback
// guess list (q, id, search, page, url) - see PHASE_4_TD_SPECS.md TD #5,
// "Relationship with Fallback Parameter List". That list is untouched by
// this file.
var knownNoiseParameters = map[string]bool{
	"utm_source":   true,
	"utm_medium":   true,
	"utm_campaign": true,
	"utm_term":     true,
	"utm_content":  true,
	"cache_bust":   true,
	"_t":           true,
}

// filterNoiseParameters returns params with any knownNoiseParameters names
// removed, preserving the original order and every other parameter
// unchanged. Matching is on the parameter name only, case-insensitive
// (still an exact, deterministic name comparison, not an inference), so
// e.g. "UTM_Source" is filtered the same as "utm_source". A nil or empty
// input is returned unchanged. Same input always yields the same output.
func filterNoiseParameters(params []string) []string {
	if len(params) == 0 {
		return params
	}
	filtered := make([]string, 0, len(params))
	for _, p := range params {
		if knownNoiseParameters[strings.ToLower(p)] {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}
