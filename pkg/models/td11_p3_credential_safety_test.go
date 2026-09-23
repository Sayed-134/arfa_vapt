package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// TD #11 — P3: Raw credential prevention.
//
// These tests validate the contract/mechanism itself (deriveSessionReference
// applied unconditionally in NewAuthContext), not heuristic secret
// detection: every input, safe or not, goes through the same one-way
// transform before it can be persisted as AuthContext.SessionRef.

const fakeRawCredential = "Bearer sk_live_super_secret_token_abc123.def456"

// Required test 1: a normal, safe principal/session reference is still
// preserved correctly - the mechanism doesn't just discard input, it
// derives a stable, meaningful reference from it.
func TestP3_NormalSafeSessionReferencePreservedCorrectly(t *testing.T) {
	ac := NewAuthContext("user-a", "config-key-session-a")
	if ac.SessionRef == "" {
		t.Fatal("expected a non-empty derived SessionRef for a normal safe reference")
	}
	// Same safe input -> same derived reference, every time.
	again := NewAuthContext("user-a", "config-key-session-a")
	if ac.SessionRef != again.SessionRef {
		t.Fatalf("expected the same safe session reference to derive the same SessionRef, got %q vs %q", ac.SessionRef, again.SessionRef)
	}
}

// Required test 2: an arbitrary secret/credential input cannot appear
// verbatim in serialized AuthContext, regardless of which field it is
// passed through.
func TestP3_RawCredentialNeverVerbatimInSerializedAuthContext(t *testing.T) {
	ac := NewAuthContext("user-a", fakeRawCredential)
	b, err := json.Marshal(ac)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), fakeRawCredential) {
		t.Fatalf("expected the raw credential to never appear verbatim in serialized AuthContext, got: %s", b)
	}
	if strings.Contains(string(b), "sk_live_super_secret_token") {
		t.Fatalf("expected no fragment of the raw credential in serialized AuthContext, got: %s", b)
	}
	if ac.SessionRef == fakeRawCredential {
		t.Fatal("expected SessionRef itself (pre-serialization) to already be the derived reference, not the raw credential")
	}
}

// Required test 3: an arbitrary secret/credential input cannot appear
// verbatim in serialized Finding (the actual TD #11 persistence surface -
// findings/history/evidence are all reached by marshaling a Finding tree).
func TestP3_RawCredentialNeverVerbatimInSerializedFinding(t *testing.T) {
	ac := NewAuthContext("attacker", fakeRawCredential)
	f := Finding{
		Category:           "IDOR",
		VerificationStatus: "LIKELY",
		AuthContext:        &ac,
		IDORComparison: &IDORComparison{
			Owner:        NewAuthContext("owner", fakeRawCredential+"-owner-variant"),
			Accessor:     ac,
			Relationship: IDORCrossPrincipalAccess,
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), fakeRawCredential) {
		t.Fatalf("expected the raw credential to never appear verbatim in a serialized Finding, got: %s", b)
	}
}

// Required test 4: the persistence path used by findings/history/evidence
// - json.Marshal on the Finding tree, which is exactly what pkg/report and
// pkg/db use to write scan_results.json / scan_history.json - cannot
// serialize raw credential material even when it is embedded several
// levels deep (Finding -> IDORComparison -> AuthContext).
func TestP3_PersistencePathCannotSerializeRawCredentialAtAnyDepth(t *testing.T) {
	deep := NewAuthContext("owner", fakeRawCredential)
	f := Finding{
		Category:           "IDOR",
		VerificationStatus: "LIKELY",
		IDORComparison: &IDORComparison{
			Owner:        deep,
			Accessor:     NewAuthContext("attacker", "attacker-sess"),
			Relationship: IDORCrossPrincipalAccess,
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), fakeRawCredential) {
		t.Fatalf("expected no raw credential at any nesting depth in the serialized Finding, got: %s", b)
	}
}

// Required test 5: context identity remains deterministic after the P3
// change (Identity's own derivation, approved under P2, is untouched).
func TestP3_ContextIdentityStillDeterministic(t *testing.T) {
	a := NewAuthContext("user-a", fakeRawCredential)
	b := NewAuthContext("user-a", fakeRawCredential)
	if a.Identity != b.Identity {
		t.Fatalf("expected identical inputs to still produce identical Identity, got %q vs %q", a.Identity, b.Identity)
	}
	if a.SessionRef != b.SessionRef {
		t.Fatalf("expected identical inputs to still produce identical derived SessionRef, got %q vs %q", a.SessionRef, b.SessionRef)
	}
}

// Required test 6: two distinct explicit principal/session contexts
// remain distinguishable after deriving SessionRef.
func TestP3_DistinctContextsStillDistinguishable(t *testing.T) {
	a := NewAuthContext("owner", fakeRawCredential)
	b := NewAuthContext("attacker", "some-other-material")
	if a.Identity == b.Identity {
		t.Fatal("expected distinct principal/session pairs to remain distinguishable by Identity")
	}
	if a.SessionRef == b.SessionRef {
		t.Fatal("expected distinct session material to remain distinguishable by derived SessionRef")
	}
}

// Required test 7: existing JSON compatibility preserved - a Finding with
// no AuthContext/IDORComparison set still omits both keys entirely.
func TestP3_ExistingJSONCompatibilityPreserved(t *testing.T) {
	f := Finding{Category: "SQL Injection", VerificationStatus: "CONFIRMED"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), "auth_context") || strings.Contains(string(b), "idor_comparison") {
		t.Fatalf("expected no auth_context/idor_comparison keys for an unrelated finding, got: %s", b)
	}
}
