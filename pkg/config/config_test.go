package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arfa.conf")
	if err := os.WriteFile(path, []byte("mode=quick\nworkers=3\nrate=2.5\nmax_pages=7\ntimeout_seconds=4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "quick" || cfg.Workers != 3 || cfg.Rate != 2.5 || cfg.MaxPages != 7 || cfg.Timeout != 4*time.Second {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arfa.conf")
	if err := os.WriteFile(path, []byte("unknown=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown key to fail")
	}
}
