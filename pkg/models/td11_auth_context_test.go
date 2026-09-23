package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// TD #11 — Auth Context Contract.
//
// These tests cover the model-level required-tests items: session context
// identifier present without raw credentials (2), same principal -> same
// identity (3), different principals -> distinguishable (4), and JSON
// compatibility (11).

func TestNewAuthContext_IdentityPresentNoRawCredentials(t *testing.T) {
	ac := NewAuthContext("user-a", "session-ref-1")
	if ac.Identity == "" {
		t.Fatal("expected a non-empty deterministic Identity")
	}
	if ac.Principal.Label != "user-a" {
		t.Fatalf("expected Principal.Label to round-trip, got %q", ac.Principal.Label)
	}
	if ac.SessionRef == "" {
		t.Fatal("expected a non-empty derived SessionRef")
	}
	// P3: SessionRef is a one-way derived reference, never the raw
	// session material verbatim (see deriveSessionReference).
	if ac.SessionRef == "session-ref-1" || strings.Contains(ac.SessionRef, "session-ref-1") {
		t.Fatal("expected SessionRef to be a derived reference, not the raw session material itself")
	}
	// AuthContext has no field capable of carrying a raw credential at
	// all - Identity is a derived hash, not the input material.
	if ac.Identity == "session-ref-1" || strings.Contains(ac.Identity, "session-ref-1") {
		t.Fatal("expected Identity to be a derived reference, not the raw SessionRef itself")
	}
}

func TestNewAuthContext_SamePrincipalAndSessionSameIdentity(t *testing.T) {
	a := NewAuthContext("user-a", "sess-1")
	b := NewAuthContext("user-a", "sess-1")
	if a.Identity != b.Identity {
		t.Fatalf("expected identical (principal, session) to produce identical Identity, got %q vs %q", a.Identity, b.Identity)
	}
}

func TestNewAuthContext_DeterministicAcrossRepeatedCalls(t *testing.T) {
	first := NewAuthContext("user-a", "sess-1").Identity
	for i := 0; i < 5; i++ {
		if got := NewAuthContext("user-a", "sess-1").Identity; got != first {
			t.Fatalf("expected NewAuthContext to be deterministic, call %d got %q, want %q", i, got, first)
		}
	}
}

func TestNewAuthContext_DifferentPrincipalsDistinguishable(t *testing.T) {
	a := NewAuthContext("user-a", "sess-1")
	b := NewAuthContext("user-b", "sess-1")
	if a.Identity == b.Identity {
		t.Fatal("expected different principal labels to produce distinguishable Identity values")
	}
}

// TestNewAuthContext_DelimiterAmbiguityFixed is a regression test for the
// corrective TD #11 patch: a naive "label|sessionRef" join let two
// distinct (principal, session) pairs collide on the same Identity
// whenever the "|" boundary could shift between them. These pairs must
// now produce distinguishable Identity values.
func TestNewAuthContext_DelimiterAmbiguityFixed(t *testing.T) {
	cases := []struct {
		aLabel, aSession string
		bLabel, bSession string
	}{
		// The exact collision named in the corrective patch spec.
		{"a|b", "c", "a", "b|c"},
		// Same total concatenation, boundary shifted by one character.
		{"ab|", "cd", "ab", "|cd"},
		// Empty-field edge cases that a naive join could also conflate.
		{"", "x|y", "x", "y"},
		{"x", "", "", "x"},
	}
	for _, c := range cases {
		a := NewAuthContext(c.aLabel, c.aSession)
		b := NewAuthContext(c.bLabel, c.bSession)
		if a.Identity == b.Identity {
			t.Fatalf("expected (%q,%q) and (%q,%q) to produce distinguishable Identity values, both got %q",
				c.aLabel, c.aSession, c.bLabel, c.bSession, a.Identity)
		}
	}
}

func TestNewAuthContext_DifferentSessionRefsDistinguishable(t *testing.T) {
	a := NewAuthContext("user-a", "sess-1")
	b := NewAuthContext("user-a", "sess-2")
	if a.Identity == b.Identity {
		t.Fatal("expected different session references (same principal) to produce distinguishable Identity values")
	}
}

// TestFinding_AuthContextOmittedWhenNilJSONCompatibility covers required
// test 11 (JSON compatibility) together with required test 10 (non-IDOR
// findings unchanged): a Finding produced without an AuthContext - i.e.
// every finding from every detector other than the new TD #11 IDOR
// entry points - must serialize with no "auth_context" key at all, so
// existing consumers of Finding JSON see no change.
func TestFinding_AuthContextOmittedWhenNilJSONCompatibility(t *testing.T) {
	f := Finding{
		ID:                 "f1",
		Category:           "XSS",
		Name:               "Reflected XSS",
		Severity:           "High",
		VerificationStatus: "CONFIRMED",
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), "auth_context") {
		t.Fatalf("expected no auth_context key for a Finding with a nil AuthContext, got: %s", b)
	}
}

// TestFinding_AuthContextJSONRoundTrip confirms an explicitly set
// AuthContext survives a JSON round trip unchanged and carries only the
// safe reference fields - no field exists on the wire capable of holding
// a raw credential.
func TestFinding_AuthContextJSONRoundTrip(t *testing.T) {
	ac := NewAuthContext("user-b", "sess-2")
	f := Finding{
		ID:                 "f2",
		Category:           "IDOR",
		VerificationStatus: "LIKELY",
		AuthContext:        &ac,
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if !strings.Contains(string(b), `"auth_context"`) {
		t.Fatalf("expected auth_context key to be present when AuthContext is set, got: %s", b)
	}
	var decoded Finding
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if decoded.AuthContext == nil {
		t.Fatal("expected AuthContext to survive the JSON round trip")
	}
	if decoded.AuthContext.Identity != ac.Identity {
		t.Fatalf("expected Identity to round-trip unchanged, got %q, want %q", decoded.AuthContext.Identity, ac.Identity)
	}
	if decoded.AuthContext.Principal.Label != "user-b" || decoded.AuthContext.SessionRef != ac.SessionRef {
		t.Fatalf("expected Principal.Label/SessionRef to round-trip unchanged, got %+v", decoded.AuthContext)
	}
	if strings.Contains(string(b), "sess-2") {
		t.Fatalf("expected the raw session material \"sess-2\" to never appear verbatim in serialized JSON, got: %s", b)
	}
}
