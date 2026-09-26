package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"arfa/pkg/models"
)

// TD #11 correction — see fingerprint()'s doc comment in scanner.go.
//
// Root cause: Category|Endpoint|Parameter|Evidence is not a sufficient
// grouping key for a cross-principal IDOR finding, because
// ScanIDORCrossPrincipal's Evidence text is a fixed template string,
// identical for every accessor compared against a given owner/endpoint/
// parameter. The dimension that actually distinguishes two such findings
// - which principal accessed the resource - lives only in
// f.IDORComparison. These tests prove that dimension now participates in
// fingerprint()'s output, and that every other finding type is completely
// unaffected.

func baseCrossPrincipalFinding() models.Finding {
	owner := models.NewAuthContext("owner-user", "owner-session")
	accessor := models.NewAuthContext("accessor-user", "accessor-session")
	return models.Finding{
		Category:  "IDOR",
		Name:      "Cross-Principal Insecure Direct Object Reference",
		Endpoint:  "http://x/profile",
		Parameter: "id",
		Evidence:  "A distinct, explicitly authenticated principal received a substantively similar, non-denial response for another principal's own identifier value",
		IDORComparison: &models.IDORComparison{
			Owner:        owner,
			Accessor:     accessor,
			Relationship: models.IDORCrossPrincipalAccess,
		},
	}
}

// TestFingerprint_DistinctAccessorsProduceDistinctIDs is the direct
// regression test for the TD #11 collision: two findings identical in
// every pre-existing fingerprint input (Category/Endpoint/Parameter/
// Evidence) but with different accessor AuthContext identities must now
// produce different fingerprints.
func TestFingerprint_DistinctAccessorsProduceDistinctIDs(t *testing.T) {
	owner := models.NewAuthContext("owner-user", "owner-session")

	f1 := baseCrossPrincipalFinding()
	f1.IDORComparison = &models.IDORComparison{
		Owner:        owner,
		Accessor:     models.NewAuthContext("accessor-a", "session-a"),
		Relationship: models.IDORCrossPrincipalAccess,
	}

	f2 := baseCrossPrincipalFinding()
	f2.IDORComparison = &models.IDORComparison{
		Owner:        owner,
		Accessor:     models.NewAuthContext("accessor-b", "session-b"),
		Relationship: models.IDORCrossPrincipalAccess,
	}

	fp1 := fingerprint(f1)
	fp2 := fingerprint(f2)
	if fp1 == fp2 {
		t.Fatalf("expected distinct accessors to produce distinct fingerprints, both got %q", fp1)
	}
}

// TestFingerprint_SameAccessorSameEverythingStillMerges confirms a true
// duplicate - identical owner, identical accessor, identical everything
// else - still produces the same fingerprint, so dedup() continues to
// correctly collapse literal repeats.
func TestFingerprint_SameAccessorSameEverythingStillMerges(t *testing.T) {
	f1 := baseCrossPrincipalFinding()
	f2 := baseCrossPrincipalFinding()

	fp1 := fingerprint(f1)
	fp2 := fingerprint(f2)
	if fp1 != fp2 {
		t.Fatalf("expected identical owner/accessor/everything to still produce the same fingerprint, got %q and %q", fp1, fp2)
	}
}

// TestFingerprint_NilIDORComparisonUnaffected is the regression guard: for
// every finding that does not carry an IDORComparison (every non-IDOR
// detector, and ScanIDOR's own single-principal heuristic findings), the
// fingerprint must be byte-for-byte identical to the pre-fix computation
// (Category|Endpoint|Parameter|Evidence only).
func TestFingerprint_NilIDORComparisonUnaffected(t *testing.T) {
	f := models.Finding{
		Category:  "XSS",
		Endpoint:  "http://x/search",
		Parameter: "q",
		Evidence:  "Payload reflected in response; context requires verification",
	}
	got := fingerprint(f)

	sum := sha256.Sum256([]byte(f.Category + "|" + f.Endpoint + "|" + f.Parameter + "|" + f.Evidence))
	h := hex.EncodeToString(sum[:8])
	if got != h {
		t.Fatalf("expected fingerprint() to match the unmodified pre-fix computation for a finding with no IDORComparison, got %q want %q", got, h)
	}
}

// TestFingerprint_Deterministic mirrors the detector-level determinism
// guarantee already proven for IDORComparison
// (TestScanIDORCrossPrincipal_RelationshipDeterministicAcrossCalls in
// pkg/detectors) at the scanner/fingerprint layer: identical inputs must
// always yield the identical fingerprint, called twice independently.
func TestFingerprint_Deterministic(t *testing.T) {
	f := baseCrossPrincipalFinding()
	fp1 := fingerprint(f)
	fp2 := fingerprint(f)
	if fp1 != fp2 {
		t.Fatalf("expected fingerprint() to be deterministic across repeated calls on identical input, got %q and %q", fp1, fp2)
	}
}

// TestDedup_CrossPrincipalFindingsForDifferentAccessorsBothSurvive is the
// scanner-level end-to-end proof: dedup() (fed findings whose IDs were
// assigned via fingerprint(), exactly as the real IDOR phase does) must
// retain both of two distinct-accessor cross-principal findings rather
// than silently dropping the second under a collided ID.
func TestDedup_CrossPrincipalFindingsForDifferentAccessorsBothSurvive(t *testing.T) {
	owner := models.NewAuthContext("owner-user", "owner-session")

	f1 := baseCrossPrincipalFinding()
	f1.IDORComparison = &models.IDORComparison{
		Owner:        owner,
		Accessor:     models.NewAuthContext("accessor-a", "session-a"),
		Relationship: models.IDORCrossPrincipalAccess,
	}
	f1.ID = fingerprint(f1)

	f2 := baseCrossPrincipalFinding()
	f2.IDORComparison = &models.IDORComparison{
		Owner:        owner,
		Accessor:     models.NewAuthContext("accessor-b", "session-b"),
		Relationship: models.IDORCrossPrincipalAccess,
	}
	f2.ID = fingerprint(f2)

	got := dedup([]models.Finding{f1, f2})
	if len(got) != 2 {
		t.Fatalf("expected both distinct-accessor cross-principal findings to survive dedup(), got %d finding(s): %+v", len(got), got)
	}
}
