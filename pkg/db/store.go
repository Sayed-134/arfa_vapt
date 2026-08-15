// Package db is Arfa's persistence layer.
//
// NOTE ON SQLITE: VISION.md and the project brief call for preserving a
// SQLite architecture. This build environment has no network access and no
// Go module cache beyond the standard library, so a SQLite driver (e.g.
// modernc.org/sqlite, the recommended pure-Go option with no cgo
// requirement) cannot be fetched here — `go get` would fail offline, and an
// unbuildable module is worse than an honest interim step. This file keeps
// the existing Open/Save API that cmd/arfa/main.go already depends on
// unchanged, but expands the underlying store to the multi-entity shape
// SQLite would eventually hold (targets, scans, findings, correlation by
// fingerprint), still backed by a single JSON file. Swapping the storage
// backend behind Open/Save for a real SQLite-backed implementation, once
// network access is available to add the dependency, is the next milestone
// — see the deliverable summary.
package db

import (
	"arfa/pkg/models"
	"encoding/json"
	"os"
	"sync"
)

// TargetSummary aggregates what the store knows about one target across all
// scans saved so far.
type TargetSummary struct {
	Target      string   `json:"target"`
	ScanCount   int      `json:"scan_count"`
	LastScanned string   `json:"last_scanned"`
	FindingIDs  []string `json:"finding_fingerprints"`
}

// FindingOccurrence is one appearance of a given finding fingerprint in a
// specific scan, used to correlate repeat/duplicate findings across runs.
type FindingOccurrence struct {
	Target    string        `json:"target"`
	StartedAt string        `json:"started_at"`
	Finding   models.Finding `json:"finding"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	results []models.ScanResult
}

// Open loads (or initializes) the store at path. Signature unchanged from
// the original single-entity store so existing callers do not need to
// change.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, e := os.ReadFile(path)
	if e == nil {
		_ = json.Unmarshal(b, &s.results)
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return s, nil
}

// Save appends a scan result and persists the store. Signature unchanged
// from the original.
func (s *Store) Save(r models.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, r)
	b, e := json.MarshalIndent(s.results, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(s.path, b, 0644)
}

// Targets summarizes every target the store has scan history for. Additive:
// existing callers that only use Open/Save are unaffected.
func (s *Store) Targets() []TargetSummary {
	s.mu.Lock()
	defer s.mu.Unlock()

	byTarget := map[string]*TargetSummary{}
	order := []string{}
	for _, r := range s.results {
		ts, ok := byTarget[r.Target]
		if !ok {
			ts = &TargetSummary{Target: r.Target}
			byTarget[r.Target] = ts
			order = append(order, r.Target)
		}
		ts.ScanCount++
		if r.StartedAt > ts.LastScanned {
			ts.LastScanned = r.StartedAt
		}
		for _, f := range r.Findings {
			ts.FindingIDs = append(ts.FindingIDs, f.ID)
		}
	}
	out := make([]TargetSummary, 0, len(order))
	for _, t := range order {
		out = append(out, *byTarget[t])
	}
	return out
}

// CorrelateFindings groups every finding ever saved by its stable
// fingerprint (models.Finding.ID), across all scans and all targets. A
// fingerprint with more than one occurrence has been seen more than once —
// either the same scan repeated, or the same underlying issue persisting
// across scans — which a report can surface instead of listing the same
// issue as if it were new each time.
func (s *Store) CorrelateFindings() map[string][]FindingOccurrence {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := map[string][]FindingOccurrence{}
	for _, r := range s.results {
		for _, f := range r.Findings {
			out[f.ID] = append(out[f.ID], FindingOccurrence{Target: r.Target, StartedAt: r.StartedAt, Finding: f})
		}
	}
	return out
}
