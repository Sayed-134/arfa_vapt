package detectors

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"arfa/pkg/models"
)

// TD #11 — Auth Context Contract, detector-level required tests.

// --- Required test 1 & 7: principal context present at IDOR probe / IDOR
// comparison records principal per probe. -----------------------------

func TestScanIDORWithContext_AttachesPrincipalContextToEveryFinding(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/profile?id=100", Method: "GET", Parameters: []string{"id"}}
	probe := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		switch value {
		case "100":
			return models.ProbeResult{Status: 200, Body: "profile for user 100 with a fair amount of content here"}
		case "99":
			return models.ProbeResult{Status: 200, Body: "profile for user 99 with a totally different amount of content here padded out"}
		default:
			return models.ProbeResult{Status: 200, Body: "not found"}
		}
	}
	authCtx := models.NewAuthContext("user-a", "sess-a")

	got := ScanIDORWithContext(context.Background(), ep, probe, &authCtx)
	if len(got) == 0 {
		t.Fatal("test precondition failed: expected at least one finding from the underlying heuristic")
	}
	for _, f := range got {
		if f.AuthContext == nil {
			t.Fatalf("expected every finding to carry the supplied AuthContext, got nil for %+v", f)
		}
		if f.AuthContext.Identity != authCtx.Identity {
			t.Fatalf("expected AuthContext.Identity to match the supplied context, got %q, want %q", f.AuthContext.Identity, authCtx.Identity)
		}
		if f.AuthContext.Principal.Label != "user-a" {
			t.Fatalf("expected AuthContext.Principal.Label to be recorded, got %q", f.AuthContext.Principal.Label)
		}
	}
}

func TestScanIDORWithContext_NilContextLeavesFindingsUnattached(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/profile?id=100", Method: "GET", Parameters: []string{"id"}}
	probe := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		if value == "99" {
			return models.ProbeResult{Status: 200, Body: "profile for user 99 with a totally different amount of content here padded out"}
		}
		return models.ProbeResult{Status: 200, Body: "profile for user 100 with a fair amount of content here"}
	}
	got := ScanIDORWithContext(context.Background(), ep, probe, nil)
	for _, f := range got {
		if f.AuthContext != nil {
			t.Fatalf("expected no AuthContext when none was supplied, got %+v", f.AuthContext)
		}
		if f.VerificationStatus != Unverified {
			t.Fatalf("expected unchanged ScanIDOR semantics (UNVERIFIED), got %s", f.VerificationStatus)
		}
	}
}

// --- Required test 9: cross-principal comparison distinguishes
// authorized (properly restricted) from unauthorized (cross-access)
// outcomes when contexts are explicit. ---------------------------------

func TestScanIDORCrossPrincipal_UnauthorizedAccessProducesLikelyFinding(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	ownerCtx := models.NewAuthContext("owner", "owner-sess")
	otherCtx := models.NewAuthContext("attacker", "attacker-sess")

	body := "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"
	owner := PrincipalProbe{Context: ownerCtx, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: body}
	}}
	// The "attacker" principal, using its own distinct, explicit
	// AuthContext, can still fetch owner's exact order - no access
	// control in effect.
	other := PrincipalProbe{Context: otherCtx, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: body, URL: "http://test/orders?id=500"}
	}}

	got := ScanIDORCrossPrincipal(context.Background(), ep, owner, []PrincipalProbe{other})
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 cross-principal finding for unauthorized access, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.VerificationStatus != "LIKELY" {
		t.Fatalf("expected VerificationStatus LIKELY for a cross-principal candidate, got %s", f.VerificationStatus)
	}
	if f.VerificationStatus == "CONFIRMED" {
		t.Fatal("cross-principal comparison must never produce CONFIRMED")
	}
	if f.AuthContext == nil || f.AuthContext.Identity != otherCtx.Identity {
		t.Fatalf("expected the finding's AuthContext to identify the accessing principal, got %+v", f.AuthContext)
	}
}

func TestScanIDORCrossPrincipal_ProperlyRestrictedProducesNoFinding(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	ownerCtx := models.NewAuthContext("owner", "owner-sess")
	otherCtx := models.NewAuthContext("attacker", "attacker-sess")

	owner := PrincipalProbe{Context: ownerCtx, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"}
	}}
	// Properly restricted: the other principal is denied.
	other := PrincipalProbe{Context: otherCtx, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: "403 Forbidden: access denied"}
	}}

	got := ScanIDORCrossPrincipal(context.Background(), ep, owner, []PrincipalProbe{other})
	if len(got) != 0 {
		t.Fatalf("expected no finding when the other principal is properly denied, got %d: %+v", len(got), got)
	}
}

// --- Required test 8: insufficient context never produces a false
// CONFIRMED (or any finding at all). ------------------------------------

func TestScanIDORCrossPrincipal_InsufficientContextNeverConfirmedOrFlagged(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	body := "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"
	owner := PrincipalProbe{Context: models.NewAuthContext("owner", "owner-sess"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: body}
	}}

	cases := []struct {
		name   string
		owner  PrincipalProbe
		others []PrincipalProbe
	}{
		{"no other principals supplied at all", owner, nil},
		{"other principal missing a Probe", owner, []PrincipalProbe{{Context: models.NewAuthContext("attacker", "s")}}},
		{"other principal missing a Context identity", owner, []PrincipalProbe{{Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: body}
		}}}},
		{"other principal shares owner's own identity", owner, []PrincipalProbe{{Context: owner.Context, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: body}
		}}}},
		{"owner probe itself denied", PrincipalProbe{Context: models.NewAuthContext("owner", "owner-sess"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: "access denied"}
		}}, []PrincipalProbe{{Context: models.NewAuthContext("attacker", "a"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: body}
		}}}},
		{"owner probe missing (no Probe, no Identity)", PrincipalProbe{}, []PrincipalProbe{{Context: models.NewAuthContext("attacker", "a"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: body}
		}}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ScanIDORCrossPrincipal(context.Background(), ep, c.owner, c.others)
			for _, f := range got {
				if f.VerificationStatus == "CONFIRMED" {
					t.Fatalf("case %q: insufficient context must never produce CONFIRMED, got %+v", c.name, f)
				}
			}
			if len(got) != 0 {
				t.Fatalf("case %q: expected no finding at all for insufficient context, got %d: %+v", c.name, len(got), got)
			}
		})
	}
}

// --- Required tests 5 & 6: raw auth token / cookie never appear in
// serialized evidence, even though the caller's probe closures use them
// to authenticate the underlying request. -------------------------------

func TestScanIDORCrossPrincipal_NoRawCredentialInSerializedFinding(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	body := "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"

	const rawBearerToken = "Bearer sk_live_super_secret_token_abc123"
	const rawCookie = "session=eyJhbGciOiJIUzI1NiJ9.super-secret-cookie-value"

	owner := PrincipalProbe{
		Context: models.NewAuthContext("owner", "owner-session-config-key"),
		Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			// The raw token is used here, by the caller, to authenticate
			// the request - it is never passed into pkg/models or
			// pkg/detectors, and never appears in the returned Finding.
			_ = rawBearerToken
			return models.ProbeResult{Status: 200, Body: body}
		},
	}
	other := PrincipalProbe{
		Context: models.NewAuthContext("attacker", "attacker-session-config-key"),
		Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			_ = rawCookie
			return models.ProbeResult{Status: 200, Body: body, URL: "http://test/orders?id=500"}
		},
	}

	got := ScanIDORCrossPrincipal(context.Background(), ep, owner, []PrincipalProbe{other})
	if len(got) != 1 {
		t.Fatalf("test precondition failed: expected 1 finding, got %d", len(got))
	}

	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	serialized := string(b)
	if strings.Contains(serialized, rawBearerToken) {
		t.Fatalf("expected no raw bearer token in serialized finding, got: %s", serialized)
	}
	if strings.Contains(serialized, rawCookie) {
		t.Fatalf("expected no raw cookie value in serialized finding, got: %s", serialized)
	}
	if strings.Contains(serialized, "super_secret") || strings.Contains(serialized, "super-secret") {
		t.Fatalf("expected no secret fragment in serialized finding, got: %s", serialized)
	}
}

// --- Required test 10: non-IDOR findings are unaffected by TD #11. -----

func TestNonIDORFindingUnaffectedByAuthContext(t *testing.T) {
	f := models.Finding{Category: "XSS", Name: "Reflected XSS", VerificationStatus: "CONFIRMED"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), "auth_context") {
		t.Fatalf("expected a non-IDOR finding to carry no auth_context key, got: %s", b)
	}
}

// --- Required test 12: concurrent use of distinct AuthContexts is race
// safe. ScanIDORCrossPrincipal holds no shared mutable state - this test
// pins that down directly, run with `go test -race`. --------------------

// --- P1: Structured IDOR comparison (IDORComparison). -------------------

func TestScanIDORCrossPrincipal_PopulatesStructuredIDORComparison(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	ownerCtx := models.NewAuthContext("owner", "owner-sess")
	otherCtx := models.NewAuthContext("attacker", "attacker-sess")
	body := "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"

	owner := PrincipalProbe{Context: ownerCtx, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: body}
	}}
	other := PrincipalProbe{Context: otherCtx, Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		return models.ProbeResult{Status: 200, Body: body, URL: "http://test/orders?id=500"}
	}}

	got := ScanIDORCrossPrincipal(context.Background(), ep, owner, []PrincipalProbe{other})
	if len(got) != 1 {
		t.Fatalf("test precondition failed: expected 1 finding, got %d", len(got))
	}
	f := got[0]

	if f.IDORComparison == nil {
		t.Fatal("expected IDORComparison to be populated for a cross-principal finding")
	}
	cmp := f.IDORComparison

	// Owner has Principal.Label + SessionRef + Identity.
	if cmp.Owner.Principal.Label != "owner" || cmp.Owner.SessionRef == "" || cmp.Owner.Identity == "" {
		t.Fatalf("expected Owner to carry Principal.Label + SessionRef + Identity, got %+v", cmp.Owner)
	}
	// Accessor has Principal.Label + SessionRef + Identity.
	if cmp.Accessor.Principal.Label != "attacker" || cmp.Accessor.SessionRef == "" || cmp.Accessor.Identity == "" {
		t.Fatalf("expected Accessor to carry Principal.Label + SessionRef + Identity, got %+v", cmp.Accessor)
	}
	// Owner and Accessor distinguishable.
	if cmp.Owner.Identity == cmp.Accessor.Identity {
		t.Fatal("expected Owner and Accessor to be distinguishable (different Identity)")
	}
	// Relationship populated deterministically.
	if cmp.Relationship != models.IDORCrossPrincipalAccess {
		t.Fatalf("expected a deterministic Relationship identifier, got %q", cmp.Relationship)
	}

	// Existing Finding.AuthContext behavior unchanged: still the accessor.
	if f.AuthContext == nil || f.AuthContext.Identity != otherCtx.Identity {
		t.Fatalf("expected Finding.AuthContext to remain the accessor's context, got %+v", f.AuthContext)
	}

	// No false CONFIRMED.
	if f.VerificationStatus == "CONFIRMED" {
		t.Fatal("expected VerificationStatus to never be CONFIRMED")
	}
}

func TestScanIDORCrossPrincipal_RelationshipDeterministicAcrossCalls(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	body := "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"
	run := func() string {
		owner := PrincipalProbe{Context: models.NewAuthContext("owner", "owner-sess"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: body}
		}}
		other := PrincipalProbe{Context: models.NewAuthContext("attacker", "attacker-sess"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
			return models.ProbeResult{Status: 200, Body: body}
		}}
		got := ScanIDORCrossPrincipal(context.Background(), ep, owner, []PrincipalProbe{other})
		if len(got) != 1 || got[0].IDORComparison == nil {
			t.Fatal("test precondition failed: expected 1 finding with IDORComparison")
		}
		return got[0].IDORComparison.Relationship
	}
	first := run()
	for i := 0; i < 3; i++ {
		if got := run(); got != first {
			t.Fatalf("expected Relationship to be deterministic across calls, got %q, want %q", got, first)
		}
	}
}

// JSON round-trip preserves the structured comparison.
func TestFinding_IDORComparisonJSONRoundTrip(t *testing.T) {
	ownerCtx := models.NewAuthContext("owner", "owner-sess")
	otherCtx := models.NewAuthContext("attacker", "attacker-sess")
	f := models.Finding{
		Category:           "IDOR",
		VerificationStatus: "LIKELY",
		AuthContext:        &otherCtx,
		IDORComparison: &models.IDORComparison{
			Owner:        ownerCtx,
			Accessor:     otherCtx,
			Relationship: models.IDORCrossPrincipalAccess,
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if !strings.Contains(string(b), `"idor_comparison"`) {
		t.Fatalf("expected idor_comparison key to be present, got: %s", b)
	}
	var decoded models.Finding
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if decoded.IDORComparison == nil {
		t.Fatal("expected IDORComparison to survive the JSON round trip")
	}
	if decoded.IDORComparison.Owner.Identity != ownerCtx.Identity {
		t.Fatalf("expected Owner.Identity to round-trip, got %q, want %q", decoded.IDORComparison.Owner.Identity, ownerCtx.Identity)
	}
	if decoded.IDORComparison.Accessor.Identity != otherCtx.Identity {
		t.Fatalf("expected Accessor.Identity to round-trip, got %q, want %q", decoded.IDORComparison.Accessor.Identity, otherCtx.Identity)
	}
	if decoded.IDORComparison.Relationship != models.IDORCrossPrincipalAccess {
		t.Fatalf("expected Relationship to round-trip, got %q", decoded.IDORComparison.Relationship)
	}
}

// ScanIDORWithContext must NOT populate IDORComparison - it is the
// single-principal path and has no accessor/owner pair to compare.
func TestScanIDORWithContext_NeverPopulatesIDORComparison(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/profile?id=100", Method: "GET", Parameters: []string{"id"}}
	probe := func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
		if value == "99" {
			return models.ProbeResult{Status: 200, Body: "profile for user 99 with a totally different amount of content here padded out"}
		}
		return models.ProbeResult{Status: 200, Body: "profile for user 100 with a fair amount of content here"}
	}
	authCtx := models.NewAuthContext("user-a", "sess-a")

	got := ScanIDORWithContext(context.Background(), ep, probe, &authCtx)
	if len(got) == 0 {
		t.Fatal("test precondition failed: expected at least one finding")
	}
	for _, f := range got {
		if f.IDORComparison != nil {
			t.Fatalf("expected ScanIDORWithContext to never populate IDORComparison, got %+v", f.IDORComparison)
		}
	}
}

// Non-IDOR findings unchanged: idor_comparison is omitted for a detector
// that never touches TD #11 at all.
func TestNonIDORFinding_IDORComparisonOmitted(t *testing.T) {
	f := models.Finding{Category: "XSS", Name: "Reflected XSS", VerificationStatus: "CONFIRMED"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	if strings.Contains(string(b), "idor_comparison") {
		t.Fatalf("expected a non-IDOR finding to carry no idor_comparison key, got: %s", b)
	}
}

func TestScanIDORCrossPrincipal_ConcurrentContextsNoRace(t *testing.T) {
	ep := models.Endpoint{URL: "http://test/orders?id=500", Method: "GET", Parameters: []string{"id"}}
	body := "order #500 details: 3 widgets, shipping to 42 Example St, total $120.00"

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := PrincipalProbe{Context: models.NewAuthContext("owner", "owner-sess"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
				return models.ProbeResult{Status: 200, Body: body}
			}}
			other := PrincipalProbe{Context: models.NewAuthContext("attacker", "sess"), Probe: func(ctx context.Context, ep models.Endpoint, param, value string) models.ProbeResult {
				return models.ProbeResult{Status: 200, Body: body}
			}}
			got := ScanIDORCrossPrincipal(context.Background(), ep, owner, []PrincipalProbe{other})
			if len(got) != 1 {
				t.Errorf("goroutine %d: expected 1 finding, got %d", i, len(got))
			}
		}(i)
	}
	wg.Wait()
}
