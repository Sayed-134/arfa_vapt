package preflight

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunReachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	cfg := Config{
		DNSTimeout:     1 * time.Second,
		ConnectTimeout: 1 * time.Second,
		HTTPTimeout:    1 * time.Second,
	}
	r := Run(context.Background(), ts.URL, cfg)
	if r.Status != Reachable {
		t.Fatalf("expected reachable, got %s (%s)", r.Status, r.Reason)
	}
}

func TestRunInvalid(t *testing.T) {
	r := Run(context.Background(), "://bad", DefaultConfig())
	if r.Status != Inconclusive {
		t.Fatalf("expected inconclusive")
	}
}

func TestUnique(t *testing.T) {
	got := unique([]string{"a", "a", "b"})
	if len(got) != 2 {
		t.Fatal(got)
	}
}
