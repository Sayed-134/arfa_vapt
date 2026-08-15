package payloads

import (
	"path/filepath"
	"testing"
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
