package payloads

import (
	"os"
	"path/filepath"
	"testing"

	"arfa/pkg/models"
)

// TD #16 — Payload corpus reproducibility/versioning.
//
// These tests use small, controlled synthetic corpora (rather than the
// large external PayloadsAllTheThings fixture) so each assertion pins down
// exactly one property of Fingerprint, per the spec's required-tests list.

func writeCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func reversedPayloads(in []models.Payload) []models.Payload {
	out := make([]models.Payload, len(in))
	for i, p := range in {
		out[len(in)-1-i] = p
	}
	return out
}

// TestFingerprint_SameCorpusStateSameFingerprint confirms loading the same
// corpus content twice (two independent Load calls, whose own traversal
// order is not guaranteed - see loader_test.go) yields an identical
// fingerprint.
func TestFingerprint_SameCorpusStateSameFingerprint(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		filepath.Join("XSS Injection", "a.txt"):    "<script>alert(1)</script>\n",
		filepath.Join("SQL Injection", "b.txt"):    "' OR '1'='1\n",
		filepath.Join("Command Injection", "c.md"): "; cat /etc/passwd\n",
	})

	first, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}

	fp1 := Fingerprint(first)
	fp2 := Fingerprint(second)
	if fp1 == "" {
		t.Fatal("expected a non-empty fingerprint for a non-empty corpus")
	}
	if fp1 != fp2 {
		t.Fatalf("expected the same corpus state to produce the same fingerprint, got %q and %q", fp1, fp2)
	}
}

// TestFingerprint_DifferentCorpusStateDifferentFingerprint confirms a
// change to corpus content (one additional payload line) changes the
// fingerprint.
func TestFingerprint_DifferentCorpusStateDifferentFingerprint(t *testing.T) {
	rootA := writeCorpus(t, map[string]string{
		filepath.Join("XSS Injection", "a.txt"): "<script>alert(1)</script>\n",
	})
	rootB := writeCorpus(t, map[string]string{
		filepath.Join("XSS Injection", "a.txt"): "<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n",
	})

	psA, err := Load(rootA)
	if err != nil {
		t.Fatal(err)
	}
	psB, err := Load(rootB)
	if err != nil {
		t.Fatal(err)
	}

	fpA := Fingerprint(psA)
	fpB := Fingerprint(psB)
	if fpA == fpB {
		t.Fatalf("expected different corpus states to produce different fingerprints, both got %q", fpA)
	}
}

// TestFingerprint_UnaffectedByNonContentTraversalOrder confirms that
// shuffling the order of an in-memory payload slice (standing in for
// Load()'s own non-deterministic map-iteration traversal order) does not
// change the fingerprint, since Fingerprint sorts its own identity lines
// before hashing.
func TestFingerprint_UnaffectedByNonContentTraversalOrder(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		filepath.Join("XSS Injection", "a.txt"):  "<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n",
		filepath.Join("SQL Injection", "b.txt"):  "' OR '1'='1\n1 UNION SELECT NULL\n",
		filepath.Join("File Inclusion", "c.txt"): "../../etc/passwd\n",
	})

	ps, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) < 3 {
		t.Fatalf("test precondition failed: expected at least 3 payloads, got %d", len(ps))
	}

	forward := Fingerprint(ps)
	got := Fingerprint(reversedPayloads(ps))
	if got != forward {
		t.Fatalf("expected traversal order to not affect the fingerprint, got %q (forward) vs %q (reversed)", forward, got)
	}
}

// TestFingerprint_ReproducibleFromKnownCorpusState pins down that
// Fingerprint is a pure function of a known corpus state: computing it
// twice from the identical, already-loaded payload slice always yields the
// same value, and that value has the shape of a sha256 hex digest.
func TestFingerprint_ReproducibleFromKnownCorpusState(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		filepath.Join("XSS Injection", "a.txt"): "<script>alert(1)</script>\n",
	})
	ps, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("expected exactly 1 payload, got %d", len(ps))
	}

	want := Fingerprint(ps)
	got := Fingerprint(ps)
	if got != want {
		t.Fatalf("expected Fingerprint to be reproducible for an identical, known corpus state, got %q and %q", got, want)
	}
	if len(want) != 64 { // sha256 hex digest length
		t.Fatalf("expected a 64-character sha256 hex fingerprint, got %d chars: %q", len(want), want)
	}
}

// TestFingerprint_EmptyCorpusIsDeterministic confirms the zero-payload edge
// case is still a stable, well-defined value (sha256 of zero bytes),
// rather than panicking or being undefined.
func TestFingerprint_EmptyCorpusIsDeterministic(t *testing.T) {
	got1 := Fingerprint(nil)
	got2 := Fingerprint([]models.Payload{})
	if got1 != got2 {
		t.Fatalf("expected nil and empty slices to produce the same fingerprint, got %q and %q", got1, got2)
	}
}
