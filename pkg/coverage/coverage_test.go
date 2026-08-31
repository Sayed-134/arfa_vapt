package coverage

import (
	"sync"
	"testing"

	"arfa/pkg/models"
)

func TestSeedThenMarkUpgrades(t *testing.T) {
	tr := New()
	k := Key{Endpoint: "http://x/a", Parameter: "id", Category: "SQLi"}
	tr.Seed(k)
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].State != models.CoverageNotAttempted {
		t.Fatalf("expected a single not_attempted entry, got %+v", snap)
	}
	tr.Mark(k, models.CoverageVerified)
	snap = tr.Snapshot()
	if snap[0].State != models.CoverageVerified {
		t.Fatalf("expected verified after Mark, got %s", snap[0].State)
	}
}

func TestMarkNeverDowngrades(t *testing.T) {
	tr := New()
	k := Key{Endpoint: "http://x/a", Parameter: "id", Category: "XSS"}
	tr.Mark(k, models.CoverageVerified)
	tr.Mark(k, models.CoverageInconclusive) // weaker; must not overwrite
	tr.Mark(k, models.CoverageAttempted)    // weaker still; must not overwrite
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].State != models.CoverageVerified {
		t.Fatalf("expected verified to survive weaker marks, got %+v", snap)
	}
}

func TestSnapshotIsDeterministicallySorted(t *testing.T) {
	tr := New()
	tr.Mark(Key{Endpoint: "http://z", Parameter: "b", Category: "XSS"}, models.CoverageAttempted)
	tr.Mark(Key{Endpoint: "http://a", Parameter: "z", Category: "LFI"}, models.CoverageAttempted)
	tr.Mark(Key{Endpoint: "http://a", Parameter: "a", Category: "SQLi"}, models.CoverageAttempted)

	first := tr.Snapshot()
	second := tr.Snapshot()
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("expected 3 entries, got %d and %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("snapshot order is not stable across calls: %+v vs %+v", first, second)
		}
	}
	if first[0].Endpoint != "http://a" || first[0].Parameter != "a" {
		t.Fatalf("expected http://a|a|SQLi to sort first, got %+v", first[0])
	}
}

func TestMarkIsSafeForConcurrentWorkers(t *testing.T) {
	tr := New()
	k := Key{Endpoint: "http://x", Parameter: "id", Category: "SQLi"}
	var wg sync.WaitGroup
	states := []models.CoverageState{models.CoverageAttempted, models.CoverageInconclusive, models.CoverageVerified, models.CoverageFailed}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(s models.CoverageState) {
			defer wg.Done()
			tr.Mark(k, s)
		}(states[i%len(states)])
	}
	wg.Wait()
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].State != models.CoverageVerified {
		t.Fatalf("expected the strongest observation (verified) to win regardless of goroutine order, got %+v", snap)
	}
}

func TestFromVerificationStatus(t *testing.T) {
	cases := map[string]models.CoverageState{
		"CONFIRMED":      models.CoverageVerified,
		"FALSE_POSITIVE": models.CoverageFailed,
		"LIKELY":         models.CoverageInconclusive,
		"POTENTIAL":      models.CoverageInconclusive,
		"INCONCLUSIVE":   models.CoverageInconclusive,
		"UNVERIFIED":     models.CoverageInconclusive,
		"":               models.CoverageAttempted,
		"garbage":        models.CoverageAttempted,
	}
	for in, want := range cases {
		if got := FromVerificationStatus(in); got != want {
			t.Errorf("FromVerificationStatus(%q) = %s, want %s", in, got, want)
		}
	}
}
