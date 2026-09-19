// Package redact provides a small, deterministic, explicit-list-based
// redaction utility for sanitizing HTTP header values before they enter a
// Finding's structured Evidence (see PHASE_4_TD_SPECS.md TD #9). It is
// intentionally shared/reusable in shape (see PHASE_4_TD_SPECS.md TD #15,
// "Shared: redaction policy مع TD #15") so a future LLM input/output
// redaction phase can reuse the same policy without re-deriving it - TD #15
// itself is not implemented by this package.
//
// Design principle: an explicit, fixed list of sensitive header names only.
// No heuristic, statistical, ML, or LLM-based inference of what "looks"
// sensitive - the same input always produces the same output, and nothing
// outside the fixed list is ever redacted.
package redact

import (
	"net/http"
	"strings"
)

// RedactedPlaceholder replaces the value of any header matched by
// sensitiveHeaderNames.
const RedactedPlaceholder = "[REDACTED]"

// sensitiveHeaderNames is the fixed, explicit set of HTTP header names
// whose value is always redacted, regardless of content. HTTP header names
// are case-insensitive (RFC 7230 §3.2), so matching below is
// case-insensitive against this lower-cased set; the set itself carries no
// other meaning and is never inferred or extended at runtime.
var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"proxy-authorization": true,
}

// Headers returns a flattened, redacted copy of h, suitable for storage in
// a Finding's Evidence. Multi-value headers are joined with ", " (the same
// separator net/http uses when rendering repeated header lines), so a
// sensitive header can never partially survive redaction by hiding a value
// in a second occurrence. A nil or empty h returns a nil map, matching
// Evidence's own omitempty contract. Deterministic: the same input always
// produces the same output, and no field is redacted based on its value -
// only on its (case-insensitive) name being in sensitiveHeaderNames.
func Headers(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for name, values := range h {
		if sensitiveHeaderNames[strings.ToLower(name)] {
			out[name] = RedactedPlaceholder
			continue
		}
		out[name] = strings.Join(values, ", ")
	}
	return out
}

// PlainHeaders behaves like Headers but for a plain, single-valued
// map[string]string input. It exists because pkg/scanner's request-header
// reconstruction (see pkg/scanner.reconstructRequestHeaders) is never a
// captured http.Header - it is a deterministically-built map of the
// headers Arfa's httpclient.Client is known to always set - so it has no
// multi-value semantics to preserve. The same fixed sensitiveHeaderNames
// list and case-insensitive matching apply.
func PlainHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for name, value := range h {
		if sensitiveHeaderNames[strings.ToLower(name)] {
			out[name] = RedactedPlaceholder
			continue
		}
		out[name] = value
	}
	return out
}
