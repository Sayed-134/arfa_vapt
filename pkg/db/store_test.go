package db

import (
	"arfa/pkg/models"
	"path/filepath"
	"testing"
)

func TestSaveAndCorrelateFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	finding := models.Finding{ID: "abc123", Category: "SQLi", Endpoint: "http://x/?id=1", Parameter: "id"}

	if err := s.Save(models.ScanResult{Target: "http://x", StartedAt: "2026-01-01T00:00:00Z", Findings: []models.Finding{finding}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(models.ScanResult{Target: "http://x", StartedAt: "2026-01-02T00:00:00Z", Findings: []models.Finding{finding}}); err != nil {
		t.Fatal(err)
	}

	corr := s.CorrelateFindings()
	occ, ok := corr["abc123"]
	if !ok {
		t.Fatal("expected fingerprint abc123 to be present")
	}
	if len(occ) != 2 {
		t.Fatalf("expected the same fingerprint to be correlated across 2 scans, got %d", len(occ))
	}

	targets := s.Targets()
	if len(targets) != 1 || targets[0].ScanCount != 2 {
		t.Fatalf("expected 1 target with 2 scans, got %+v", targets)
	}

	// Reopening from disk should preserve saved history.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.CorrelateFindings()["abc123"]) != 2 {
		t.Fatal("expected correlation to survive reopening the store from disk")
	}
}
