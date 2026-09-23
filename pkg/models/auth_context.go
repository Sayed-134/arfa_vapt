package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
)

// AuthPrincipal identifies, by a safe operator-supplied label, the identity
// under which a probe was executed (TD #11 — IDOR authenticated
// principal/session context; see PHASE_4_TD_SPECS.md). Label is a
// reference chosen by the operator/test setup (e.g. "user-a", "admin") -
// it is never a credential, token, or cookie value, and nothing in this
// package ever derives a Label automatically or persists raw auth
// material behind one.
type AuthPrincipal struct {
	// Label is the operator-supplied, human-readable reference for this
	// principal. It must never be set to a raw credential, token, or
	// cookie value.
	Label string `json:"label"`
}

// AuthContext is a safe, non-secret reference to the authenticated
// session/auth material a probe executed under, plus the AuthPrincipal it
// belongs to. AuthContext never carries the raw credential/token/cookie
// itself - only operator-supplied references (Principal.Label,
// SessionRef) and a deterministic Identity computed from them (see
// NewAuthContext). The actual auth material needed to make an
// authenticated request (e.g. a header value) is the caller's concern,
// bound into the probe closure that executes under this AuthContext - it
// is never stored on, or reachable from, an AuthContext value.
type AuthContext struct {
	Principal AuthPrincipal `json:"principal"`

	// SessionRef is a non-secret, deterministically *derived* reference
	// identifying which session/auth material this context represents
	// (see NewAuthContext / deriveSessionReference). It is never the raw
	// session material the caller supplied - NewAuthContext one-way
	// hashes that material before it is ever assigned here, so even a
	// caller that mistakenly passes a real token/cookie value can never
	// cause it to be persisted or serialized verbatim through this
	// field: recovering the original input from SessionRef is as hard as
	// reversing sha256. Optional: empty when the caller supplies no
	// session material to distinguish multiple sessions for the same
	// Principal.
	SessionRef string `json:"session_ref,omitempty"`

	// Identity is a deterministic, non-secret reference for this exact
	// AuthContext (see NewAuthContext): the same Principal.Label +
	// SessionRef always produce the same Identity, and a different
	// Principal.Label or SessionRef always produces a different
	// Identity. It is derived only from those two operator-supplied
	// references, never from raw credential material, so it is safe to
	// serialize and attach to a Finding/Evidence.
	Identity string `json:"identity"`
}

// NewAuthContext builds an AuthContext for the given operator-supplied
// principal label and session material, computing a deterministic
// Identity from them (unchanged from the approved P2 fix - see
// writeCanonicalField) and a one-way derived SessionRef (see
// deriveSessionReference).
//
// principalLabel must be a safe, human-readable reference, not a
// credential (see AuthPrincipal.Label) - NewAuthContext performs no
// transformation on it, since a caller-facing display label has no way to
// be made "safe by construction" without destroying its purpose.
//
// sessionRef, by contrast, is the parameter that names the actual
// session/auth material to distinguish (a cookie, token, or session
// label) - exactly the value the TD #11 spec requires never be persisted
// verbatim. NewAuthContext therefore never stores sessionRef itself:
// AuthContext.SessionRef always holds deriveSessionReference(sessionRef),
// a one-way hash-derived reference, so whatever a caller passes here -
// even a real raw token or cookie value passed by mistake - can never
// appear verbatim in the resulting AuthContext, and therefore never in
// any Finding/Evidence/history that embeds it. This is a deterministic,
// content-agnostic transform (applied to every input identically, never a
// heuristic judgment about whether the input "looks like" a secret), so
// same (principalLabel, sessionRef) still always yields the same
// Identity/SessionRef, and a different pair still always yields different
// values (barring a sha256 collision).
func NewAuthContext(principalLabel, sessionRef string) AuthContext {
	h := sha256.New()
	writeCanonicalField(h, principalLabel)
	writeCanonicalField(h, sessionRef)
	return AuthContext{
		Principal:  AuthPrincipal{Label: principalLabel},
		SessionRef: deriveSessionReference(sessionRef),
		Identity:   hex.EncodeToString(h.Sum(nil)),
	}
}

// deriveSessionReference produces AuthContext.SessionRef's persisted
// value: a non-secret, deterministic reference derived one-way from
// sessionMaterial via sha256, never sessionMaterial itself. Applied
// uniformly to every input regardless of content - this is a mechanical
// transform, not a judgment about whether sessionMaterial "looks like" a
// secret - so it provides the same guarantee whether sessionMaterial is
// an innocuous label or an actual raw credential a caller passed by
// mistake: only the derived reference below is ever stored, and
// recovering sessionMaterial from it is computationally infeasible.
func deriveSessionReference(sessionMaterial string) string {
	if sessionMaterial == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("td11-session-ref|" + sessionMaterial))
	return "ref:" + hex.EncodeToString(sum[:])
}

// IDORCrossPrincipalAccess is the deterministic Relationship value
// ScanIDORCrossPrincipal assigns to every IDORComparison it produces: an
// Accessor, under its own distinct explicit AuthContext, received a
// substantively similar, non-denial response for a resource identified by
// Owner's own identifier value. It is a fixed identifier, not free-form
// text - the same comparison scenario always yields this same value.
const IDORCrossPrincipalAccess = "cross_principal_access"

// IDORComparison structurally represents a TD #11 cross-principal IDOR
// comparison outcome, replacing free-form text as the record of which two
// principals/sessions were compared and how. It is additive: existing
// Finding.AuthContext (the accessor's context, for the pre-existing
// single-principal and cross-principal paths) is unchanged by
// IDORComparison's presence.
type IDORComparison struct {
	// Owner is the full AuthContext under which the resource being
	// compared was accessed as its own/baseline resource.
	Owner AuthContext `json:"owner"`

	// Accessor is the full AuthContext of the principal whose access to
	// Owner's resource is being evaluated. Always a distinct AuthContext
	// from Owner (see ScanIDORCrossPrincipal) - same-principal access is
	// not a cross-principal comparison.
	Accessor AuthContext `json:"accessor"`

	// Relationship is a deterministic, fixed identifier naming the kind
	// of comparison this record represents (see IDORCrossPrincipalAccess)
	// - never free-form text.
	Relationship string `json:"relationship"`
}

// writeCanonicalField writes s into h preceded by its own byte length
// (netstring-style length-prefix framing: "<len>:<bytes>"), so that
// hashing two fields back to back can never be ambiguous regardless of
// what characters either field contains.
//
// The previous encoding joined fields with a plain "|" separator
// ("label|sessionRef"), which meant two different (principalLabel,
// sessionRef) pairs whose concatenation happened to line up around a "|"
// produced the *same* hashed bytes and therefore the same Identity - e.g.
// principalLabel="a|b", sessionRef="c" encoded identically to
// principalLabel="a", sessionRef="b|c". Prefixing each field with its own
// length removes that ambiguity: the decoded field boundaries are fixed
// by the length prefixes, not by scanning for a separator character that
// could also appear inside a field's own content.
func writeCanonicalField(h hash.Hash, s string) {
	fmt.Fprintf(h, "%d:", len(s))
	h.Write([]byte(s))
}
