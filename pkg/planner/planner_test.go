package planner

import (
	"testing"

	"arfa/pkg/models"
)

func TestPlan_OnlyInconclusiveAndNotAttemptedAreActionable(t *testing.T) {
	cov := []models.CoverageEntry{
		{Endpoint: "http://x/a", Parameter: "id", Category: "SQLi", State: models.CoverageVerified},
		{Endpoint: "http://x/b", Parameter: "q", Category: "XSS", State: models.CoverageFailed},
		{Endpoint: "http://x/c", Parameter: "f", Category: "LFI", State: models.CoverageInconclusive},
		{Endpoint: "http://x/d", Parameter: "u", Category: "SSRF", State: models.CoverageNotAttempted},
	}
	actions := Plan(cov, 10)
	if len(actions) != 2 {
		t.Fatalf("expected exactly 2 actionable entries (verified/failed excluded), got %d: %+v", len(actions), actions)
	}
	for _, a := range actions {
		if a.Category == "SQLi" || a.Category == "XSS" {
			t.Fatalf("resolved (verified/failed) entries must never be suggested, got %+v", a)
		}
	}
}

func TestPlan_InconclusiveOutranksNotAttempted(t *testing.T) {
	cov := []models.CoverageEntry{
		{Endpoint: "http://x/z", Parameter: "z", Category: "SSRF", State: models.CoverageNotAttempted},
		{Endpoint: "http://x/a", Parameter: "a", Category: "LFI", State: models.CoverageInconclusive},
	}
	actions := Plan(cov, 10)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
	if actions[0].Category != "LFI" {
		t.Fatalf("expected inconclusive (LFI) to rank first regardless of alphabetical endpoint order, got %+v", actions[0])
	}
}

func TestPlan_DeterministicOrderAcrossCalls(t *testing.T) {
	cov := []models.CoverageEntry{
		{Endpoint: "http://x/c", Parameter: "p", Category: "XSS", State: models.CoverageNotAttempted},
		{Endpoint: "http://x/a", Parameter: "p", Category: "XSS", State: models.CoverageNotAttempted},
		{Endpoint: "http://x/b", Parameter: "p", Category: "XSS", State: models.CoverageNotAttempted},
	}
	first := Plan(cov, 10)
	second := Plan(cov, 10)
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("Plan is not deterministic across identical calls: %+v vs %+v", first, second)
		}
	}
	if first[0].Endpoint != "http://x/a" || first[1].Endpoint != "http://x/b" || first[2].Endpoint != "http://x/c" {
		t.Fatalf("expected alphabetical tiebreak within equal priority, got %+v", first)
	}
}

func TestPlan_IsBounded(t *testing.T) {
	cov := make([]models.CoverageEntry, 0, 100)
	for i := 0; i < 100; i++ {
		cov = append(cov, models.CoverageEntry{Endpoint: "http://x", Parameter: "p", Category: "XSS", State: models.CoverageNotAttempted})
	}
	if got := len(Plan(cov, 5)); got != 5 {
		t.Fatalf("expected Plan to cap output at maxActions=5, got %d", got)
	}
	if got := len(Plan(cov, 0)); got != DefaultMaxActions {
		t.Fatalf("expected maxActions<=0 to fall back to DefaultMaxActions=%d, got %d", DefaultMaxActions, got)
	}
}

func TestPlan_EmptyCoverageReturnsEmpty(t *testing.T) {
	if actions := Plan(nil, 10); len(actions) != 0 {
		t.Fatalf("expected no actions for empty coverage, got %+v", actions)
	}
}
