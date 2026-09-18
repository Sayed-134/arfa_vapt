package payloads

import (
	"os"
	"path/filepath"
	"testing"

	"arfa/pkg/models"
)

func TestLoadSuppliedRepository(t *testing.T) {
	root := filepath.Join("..", "..", "payloads-database", "PayloadsAllTheThings-master")
	ps, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	g := Group(ps)
	for _, cat := range []string{"XSS", "SQLi", "LFI", "RCE", "SSRF", "SSTI", "XXE", "CRLF", "Open Redirect"} {
		if len(g[cat]) == 0 {
			t.Fatalf("expected payloads for %s", cat)
		}
	}
}

// TD #6 — Payload corpus structured metadata.

// TestLoadWithTempCorpusPopulatesExpectedMetadata uses a small, controlled
// synthetic corpus (rather than the large external PayloadsAllTheThings
// fixture) to pin down exactly what TD #6's additive metadata fields
// contain and confirm the existing ID/Category/Value/Source contract is
// unchanged.
func TestLoadWithTempCorpusPopulatesExpectedMetadata(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "XSS Injection")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payloads.txt"), []byte("<script>alert(1)</script>\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ps, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("expected exactly 1 payload, got %d", len(ps))
	}
	p := ps[0]

	// Existing contract: unchanged.
	if p.Category != "XSS" {
		t.Fatalf("expected unchanged Category=XSS, got %q", p.Category)
	}
	if p.Value != "<script>alert(1)</script>" {
		t.Fatalf("expected unchanged Value, got %q", p.Value)
	}
	if p.Source != filepath.Join(dir, "payloads.txt") {
		t.Fatalf("expected unchanged Source, got %q", p.Source)
	}

	// New, additive metadata: correct for this known corpus layout.
	wantCorpusName := filepath.Base(root)
	if p.CorpusName != wantCorpusName {
		t.Fatalf("expected CorpusName=%q, got %q", wantCorpusName, p.CorpusName)
	}
	if p.CorpusCategory != "XSS Injection" {
		t.Fatalf("expected CorpusCategory=%q, got %q", "XSS Injection", p.CorpusCategory)
	}
	if p.FileType != "txt" {
		t.Fatalf("expected FileType=txt, got %q", p.FileType)
	}
}

// TestLoadCorpusMetadataDeterministicAcrossLoads confirms loading the same
// corpus twice yields identical metadata - no randomness, no hidden state.
func TestLoadCorpusMetadataDeterministicAcrossLoads(t *testing.T) {
	root := filepath.Join("..", "..", "payloads-database", "PayloadsAllTheThings-master")
	first, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("expected a stable, non-empty payload count across loads, got %d and %d", len(first), len(second))
	}

	// Load()'s category loop ranges over the dirs map, whose iteration
	// order is randomized by Go per range - independently for the first
	// and second call - so slice position is not guaranteed to match
	// across calls, only the set of payloads and each payload's own
	// fields are. This is pre-existing Load() behavior, unrelated to TD
	// #6's metadata fields, so compare by ID (itself a deterministic
	// hash of category+value) instead of by index.
	byID := make(map[string]models.Payload, len(second))
	for _, p := range second {
		byID[p.ID] = p
	}

	for _, p := range first {
		match, ok := byID[p.ID]
		if !ok {
			t.Fatalf("payload %q present in the first load was missing from the second load", p.ID)
		}
		if p.Category != match.Category || p.Value != match.Value || p.Source != match.Source {
			t.Fatalf("expected existing ID/Category/Value/Source to be preserved across loads for payload %q", p.ID)
		}
		if p.CorpusName != match.CorpusName || p.CorpusCategory != match.CorpusCategory || p.FileType != match.FileType {
			t.Fatalf("expected TD #6 corpus metadata to be deterministic across loads for payload %q", p.ID)
		}
	}
}

// TestLoadCorpusCategoryMatchesKnownDirectoryNames confirms CorpusCategory
// is only ever one of the corpus directory names the loader itself already
// knows about (the dirs map) - never an invented or guessed value.
func TestLoadCorpusCategoryMatchesKnownDirectoryNames(t *testing.T) {
	root := filepath.Join("..", "..", "payloads-database", "PayloadsAllTheThings-master")
	ps, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, names := range dirs {
		for _, n := range names {
			known[n] = true
		}
	}
	for _, p := range ps {
		if !known[p.CorpusCategory] {
			t.Fatalf("expected CorpusCategory %q to be one of the known corpus directory names, for payload %q", p.CorpusCategory, p.ID)
		}
		if p.FileType != "txt" && p.FileType != "md" {
			t.Fatalf("expected FileType to be txt or md (the loader's existing file-type filter), got %q for payload %q", p.FileType, p.ID)
		}
	}
}
