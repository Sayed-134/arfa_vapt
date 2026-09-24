// Package db is Arfa's persistence layer.
//
// NOTE ON SQLITE: VISION.md and the project brief call for preserving a
// SQLite architecture. This build environment has no network access and no
// Go module cache beyond the standard library, so a SQLite driver (e.g.
// modernc.org/sqlite, the recommended pure-Go option with no cgo
// requirement) cannot be fetched here — `go get` would fail offline, and an
// unbuildable module is worse than an honest interim step. This file keeps
// the existing Open/Save API that cmd/arfa/main.go already depends on
// source-compatible, but expands the underlying store to the multi-entity
// shape SQLite would eventually hold (targets, scans, findings, correlation
// by fingerprint), still backed by a single JSON file. Swapping the storage
// backend behind Open/Save for a real SQLite-backed implementation, once
// network access is available to add the dependency, remains a future
// milestone.
//
// TD #12 (History Storage Persistence/Locking/Retention) evolved this same
// store in place — no new storage subsystem — to add atomic writes, a
// cross-process advisory lock around the read-modify-write-back cycle,
// stable per-record scan identity, and a configurable retention policy.
// See each function's doc comment for the specific guarantee it provides.
package db

import (
	"arfa/pkg/models"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// defaultMaxRecords is the retention bound applied when a Store is opened
// with no explicit retention Option. The spec only requires that the store
// never grow unbounded by default (TD #12 requirement #5) - it does not
// mandate a specific number, so 1000 is this package's own implementation
// choice, made on the following rationale:
//
//   - ARFA's history store is local-first and single-operator (see
//     ARFA_MASTER_CONTEXT.md/PLATFORM_STRATEGY.md - no distributed
//     dependency is in scope). A single operator running authorized scans
//     against a handful of targets is not expected to accumulate more than
//     a few scans a day even under heavy use, so 1000 records comfortably
//     covers roughly a year of daily scanning before the count-based bound
//     ever engages.
//   - The whole store is one JSON file loaded fully into memory on every
//     Open and rewritten fully on every Save (see writeRecordsAtomic). At
//     1000 records the file stays in the low tens of MB even for
//     large/deep scans, which keeps Open/Save latency predictable and
//     load times fast - the property this bound exists to protect, per
//     the spec's "no unbounded growth".
//   - It is a default, not a ceiling: WithMaxRecords/WithMaxAge override
//     it per Store, and MaxRecords <= 0 disables the count bound entirely
//     for a caller that explicitly wants unbounded local history.
const defaultMaxRecords = 1000

// lockRetryInterval/defaultLockTimeout bound the cross-process advisory
// lock used by Save (see (*Store).lock). A bounded wait, rather than an
// unbounded one, means a stuck/crashed holder becomes an observable error
// instead of a silent hang - see TD #12 requirement #6, "Failure
// handling". defaultLockTimeout is overridable per Store via
// WithLockTimeout; see that Option's doc comment for why it exists
// alongside the stale-lock reclamation in reclaimAbandonedLock rather than
// being redundant with it.
const (
	lockRetryInterval  = 10 * time.Millisecond
	defaultLockTimeout = 5 * time.Second
	// staleLockAge is how old a lock file's own recorded creation time
	// must be before its holder is even considered for abandonment. It is
	// deliberately a large multiple of how long a Save's critical section
	// (read the current file, append, apply retention, atomic write)
	// actually takes on local disk - realistically well under a second,
	// even for a history file at the defaultMaxRecords cap - so a lock
	// this old is never a legitimately slow in-progress Save, only a
	// holder that stopped running. See reclaimAbandonedLock: age alone is
	// still never sufficient by itself to reclaim a lock.
	staleLockAge = 30 * time.Second
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
	Target    string         `json:"target"`
	StartedAt string         `json:"started_at"`
	Finding   models.Finding `json:"finding"`
}

// Record is one persisted history entry: the scanner's own ScanResult plus
// storage-layer metadata added by TD #12. Record wraps models.ScanResult
// rather than adding fields to it, so the core ScanEnvelope/Finding
// contracts are untouched - the extra identity/timestamp fields are a
// pkg/db concern only.
type Record struct {
	// ID uniquely identifies this record within the store, so a record is
	// never overwritten or confused with another by coincidence (TD #12
	// requirement #4, "Stable scan identity").
	ID string `json:"id"`
	// SavedAt is when this record was written, used by the age-based
	// retention policy.
	SavedAt string            `json:"saved_at"`
	Result  models.ScanResult `json:"result"`
}

// RetentionPolicy bounds how many records, and/or how old the records in
// the store may be. Zero (the zero value for a field) means "no limit" for
// that dimension. Applied after every Save (TD #12 requirement #5).
type RetentionPolicy struct {
	// MaxRecords keeps at most the N most-recently-saved records. <= 0
	// disables the count-based bound.
	MaxRecords int
	// MaxAge discards records whose SavedAt is older than MaxAge. <= 0
	// disables the age-based bound.
	MaxAge time.Duration
}

// Option configures a Store at Open time. Existing callers using
// db.Open(path) with no options are unaffected and receive the default
// retention policy (defaultMaxRecords) - see Open.
type Option func(*Store)

// WithMaxRecords overrides the store's count-based retention bound. n <= 0
// disables it (unbounded by count).
func WithMaxRecords(n int) Option {
	return func(s *Store) { s.retention.MaxRecords = n }
}

// WithMaxAge sets the store's age-based retention bound. d <= 0 disables it
// (unbounded by age).
func WithMaxAge(d time.Duration) Option {
	return func(s *Store) { s.retention.MaxAge = d }
}

// WithLockTimeout overrides how long Save waits to acquire the
// cross-process lock before failing (default defaultLockTimeout). This is
// a distinct knob from staleLockAge/reclaimAbandonedLock: lock timeout
// bounds how long *this* caller is willing to wait, win or lose, while
// staleLockAge decides whether a lock *can* be reclaimed from a confirmed-
// dead holder at all. Raising the timeout gives a legitimately busy,
// still-alive holder more time to finish; it does not change whether an
// abandoned lock is ever recognized as such. d <= 0 is rejected (falls
// back to the default) rather than silently producing a lock that never
// times out, which would reintroduce the unbounded hang TD #12 exists to
// remove.
func WithLockTimeout(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.lockTimeout = d
		}
	}
}

type Store struct {
	// mu guards this Store handle's in-memory cache (results). It does not
	// by itself make concurrent Save calls across separate Store handles
	// (e.g. two arfa processes, or two Open() calls in the same process)
	// safe - that is the job of the cross-process lock file (see lock).
	mu          sync.Mutex
	path        string
	lockPath    string
	lockTimeout time.Duration
	retention   RetentionPolicy
	results     []Record
}

// Open loads (or initializes) the store at path, creating its parent
// directory deterministically if needed (TD #12 requirement #10). The
// signature stays source-compatible with the pre-TD #12 db.Open(path) call
// in cmd/arfa/main.go: opts is variadic, so existing call sites compile
// and behave the same, receiving the default retention policy.
//
// Open does not take the cross-process lock (see (*Store).lock) before its
// read. It does not need to: the canonical file is never modified in
// place - every write goes through writeRecordsAtomic's temp-file-then-
// rename, so at any instant the path either has last write's complete
// contents or this write's complete contents, never a partial one (see
// readRecords/writeRecordsAtomic). A concurrent Open therefore always
// reads a safe, complete snapshot; at worst it is a snapshot that a
// same-instant Save is about to supersede, which is the ordinary and
// unavoidable staleness of any read concurrent with a write, not a
// correctness gap the lock would close.
func Open(path string, opts ...Option) (*Store, error) {
	s := &Store{
		path:        path,
		lockPath:    path + ".lock",
		lockTimeout: defaultLockTimeout,
		retention:   RetentionPolicy{MaxRecords: defaultMaxRecords},
	}
	for _, opt := range opts {
		opt(s)
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("db: initializing storage directory: %w", err)
		}
	}

	recs, err := readRecords(path)
	if err != nil {
		return nil, err
	}
	s.results = recs
	return s, nil
}

// Save appends a scan result as a new Record and persists the store.
// History is best-effort by design (the caller in cmd/arfa/main.go already
// treats a history error as non-fatal to the scan itself - TD #12
// requirement #9), but every failure is returned rather than swallowed
// here, so a caller that does check it can observe and act on it (TD #12
// requirement #6).
//
// The read-modify-write-back cycle - read the current on-disk records,
// append, apply retention, write back - runs under a cross-process lock
// (see lock) so concurrent Save calls, whether from goroutines in this
// process or from another arfa process pointed at the same history file,
// serialize instead of one silently clobbering another's append (TD #12
// requirement #3). The write-back itself is atomic (see writeRecordsAtomic)
// so a crash or interruption mid-write can never leave a corrupt canonical
// file (TD #12 requirement #2).
func (s *Store) Save(r models.ScanResult) error {
	id, err := newScanID()
	if err != nil {
		return err
	}
	rec := Record{ID: id, SavedAt: time.Now().UTC().Format(time.RFC3339), Result: r}

	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	current, err := readRecords(s.path)
	if err != nil {
		return err
	}
	current = append(current, rec)
	current = applyRetention(current, s.retention)

	if err := writeRecordsAtomic(s.path, current); err != nil {
		return err
	}

	s.mu.Lock()
	s.results = current
	s.mu.Unlock()
	return nil
}

// Targets summarizes every target the store has scan history for. Additive:
// existing callers that only use Open/Save are unaffected.
func (s *Store) Targets() []TargetSummary {
	s.mu.Lock()
	defer s.mu.Unlock()

	byTarget := map[string]*TargetSummary{}
	order := []string{}
	for _, rec := range s.results {
		r := rec.Result
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
	for _, rec := range s.results {
		r := rec.Result
		for _, f := range r.Findings {
			out[f.ID] = append(out[f.ID], FindingOccurrence{Target: r.Target, StartedAt: r.StartedAt, Finding: f})
		}
	}
	return out
}

// lockMeta is the content written into a lock file at acquisition time.
// Recording both PID and creation time - rather than relying on the lock
// file's filesystem mtime, which third-party tools or a filesystem copy
// could alter - is what lets reclaimAbandonedLock apply a deterministic,
// two-signal contract for whether an existing lock was abandoned by a
// crashed process, instead of guessing from a single, individually
// ambiguous signal (see reclaimAbandonedLock).
type lockMeta struct {
	PID       int    `json:"pid"`
	CreatedAt string `json:"created_at"`
}

// lock acquires an exclusive, cross-process advisory lock for this store's
// path using a sibling ".lock" file created with O_EXCL: file creation with
// O_EXCL is atomic, so exactly one caller - across goroutines and across
// separate arfa processes pointed at the same history file - ever holds the
// lock at a time. The lock file's content records this holder's PID and
// creation time (lockMeta) so a *later* caller that finds the lock already
// held can evaluate whether it was abandoned - see reclaimAbandonedLock.
//
// The wait for acquisition is bounded by s.lockTimeout (default
// defaultLockTimeout, overridable via WithLockTimeout): on each failed
// attempt, an abandoned lock is reclaimed immediately if one is found
// (retrying acquisition without spending any of the remaining wait), and
// otherwise the loop backs off and re-checks the deadline. Either way,
// lock never blocks forever - a stuck or crashed holder becomes an
// observable failure (TD #12 requirement #6) instead of a silent hang.
func (s *Store) lock() (unlock func(), err error) {
	deadline := time.Now().Add(s.lockTimeout)
	for {
		f, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			meta := lockMeta{PID: os.Getpid(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			// Best-effort: an unwritten/unreadable lock body only ever
			// weakens a *future* caller's ability to reclaim this lock if
			// it were abandoned - it never weakens the mutual-exclusion
			// guarantee itself, which O_EXCL above already provides.
			if b, mErr := json.Marshal(meta); mErr == nil {
				_, _ = f.Write(b)
			}
			_ = f.Close()
			return func() { _ = os.Remove(s.lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("db: acquiring lock: %w", err)
		}
		if reclaimAbandonedLock(s.lockPath) {
			continue // an abandoned lock was just removed; retry acquiring immediately
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("db: timed out waiting for lock on %s after %s", s.path, s.lockTimeout)
		}
		time.Sleep(lockRetryInterval)
	}
}

// reclaimAbandonedLock inspects the lock file at lockPath and removes it
// only when BOTH of the following hold - this is the corrective fix for
// TD #12's original lock, which had no handling at all for a .lock left
// behind by a crashed process:
//
//   - age: the lock's own recorded creation time is older than
//     staleLockAge - a generous multiple of how long a Save critical
//     section actually takes, so this is never mistaken for an in-progress
//     Save;
//   - liveness: the PID recorded in the lock file is positively confirmed
//     dead (see processAlive).
//
// Neither signal is used alone. Age alone is not sufficient: a
// legitimately slow holder (heavy disk load, a huge legacy history file
// being adopted) would be wrongly declared abandoned. PID alone is not
// sufficient either: PID reuse after a crash means a live PID does not
// prove the *original* holder is still the one running, and conversely a
// PID this process cannot currently see as alive is the only outcome
// treated as meaningful - anything ambiguous is left alone. This is why
// processAlive is intentionally conservative (defaults to "alive" on any
// inconclusive result): reclaimAbandonedLock must only ever remove a lock
// it can positively justify as dead, never one it merely suspects.
//
// If the lock file cannot be read or parsed - most commonly because
// another caller is concurrently mid-way through creating it, a benign
// and expected race - it is left alone; an unreadable lock is not evidence
// of abandonment, only of a race this function does not need to resolve
// (the normal retry loop in lock already handles it). Returns true if it
// removed a lock, telling the caller to retry acquisition immediately
// rather than sleep first.
func reclaimAbandonedLock(lockPath string) bool {
	info, statErr := os.Stat(lockPath)
	if statErr != nil {
		return false
	}
	b, err := os.ReadFile(lockPath)
	if err != nil || len(b) == 0 {
		return false
	}
	var meta lockMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return false
	}
	created, err := time.Parse(time.RFC3339Nano, meta.CreatedAt)
	if err != nil {
		// The recorded timestamp itself is unreadable; fall back to the
		// file's own mtime rather than treating a malformed-but-present
		// lock as automatically stale.
		created = info.ModTime()
	}
	if time.Since(created) < staleLockAge {
		return false
	}
	if processAlive(meta.PID) {
		return false
	}
	// Another caller may have already reclaimed this exact lock between
	// the Stat/Read above and here; a "already gone" result from Remove is
	// that benign race, not a failure of this reclamation.
	if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
		return false
	}
	return true
}

// processAlive reports whether pid is confirmed to be a live process,
// probed via signal 0 (proc.Signal(syscall.Signal(0))): no signal is
// actually delivered, this only tests whether the OS still has a process
// at that PID that this process is permitted to signal. It is
// deliberately conservative - every ambiguous outcome (pid <= 0, a lookup
// error, permission denied, or a probe that is not supported at all on
// this platform, which is the case on Windows for any signal other than
// os.Kill/os.Interrupt) is treated as "alive", because the only caller,
// reclaimAbandonedLock, must never remove a lock it cannot positively
// prove is dead. The only outcomes treated as a confirmed death are Go's
// own os.ErrProcessDone and a Unix ESRCH ("no such process") errno -
// both compile on every platform Go supports (including Windows, where
// ESRCH is simply never the error actually returned), so this function
// needs no platform-specific build files.
func processAlive(pid int) bool {
	if pid <= 0 {
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrProcessDone) {
		return false
	}
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.ESRCH {
		return false
	}
	return true
}

// readRecords loads every record currently on disk at path. A missing file
// is treated as an empty store (first run), not an error - matching the
// original store's behavior for a fresh scan_history.json.
//
// For backward compatibility with a history file written before TD #12 (a
// plain JSON array of models.ScanResult, with no wrapping Record), the
// format is determined explicitly from the first array element rather than
// by "try []Record and see if it errors": encoding/json silently zero-fills
// struct fields that are absent from the JSON, so unmarshaling a legacy
// ScanResult array into []Record would not fail - it would quietly succeed
// with every Record's fields empty. A TD #12 Record always serializes with
// a top-level "result" key; a legacy ScanResult never does, so checking for
// that key's presence is what actually distinguishes the two schemas. A
// legacy file's entries are adopted additively: each is wrapped into a
// Record with a freshly generated ID and SavedAt taken from its own
// StartedAt, keeping an existing history file readable without a migration
// step, per TD #12's "no new storage subsystem, additive schema"
// requirement.
func readRecords(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("db: %s is not a valid history file: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw[0], &probe); err != nil {
		return nil, fmt.Errorf("db: %s is not a valid history file: %w", path, err)
	}

	if _, isRecord := probe["result"]; isRecord {
		var recs []Record
		if err := json.Unmarshal(b, &recs); err != nil {
			return nil, fmt.Errorf("db: %s is not a valid history file: %w", path, err)
		}
		return recs, nil
	}

	var legacy []models.ScanResult
	if err := json.Unmarshal(b, &legacy); err != nil {
		return nil, fmt.Errorf("db: %s is neither a valid TD #12 record array nor a legacy scan result array: %w", path, err)
	}
	recs := make([]Record, 0, len(legacy))
	for _, r := range legacy {
		id, idErr := newScanID()
		if idErr != nil {
			return nil, idErr
		}
		recs = append(recs, Record{ID: id, SavedAt: r.StartedAt, Result: r})
	}
	return recs, nil
}

// writeRecordsAtomic persists recs to path by writing to a temp file in the
// same directory (so the final rename is same-filesystem and therefore
// atomic on every platform Go supports) and renaming it over path. A
// reader can only ever observe the previous complete file or the new
// complete file - never a partially-written one - satisfying TD #12
// requirement #2 (atomic writes) and requirement #3's "readers never see a
// partial record".
func writeRecordsAtomic(path string, recs []Record) error {
	if recs == nil {
		recs = []Record{}
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("db: creating temp file for atomic write: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("db: writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("db: syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("db: closing temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		return fmt.Errorf("db: setting temp file permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("db: renaming temp file into place: %w", err)
	}
	return nil
}

// applyRetention returns recs trimmed to the given RetentionPolicy. Age
// trimming runs first (dropping only records older than MaxAge), then
// count trimming keeps only the MaxRecords most-recent survivors - so
// retention only ever removes older records, never a record newer than one
// it kept (TD #12 requirement: "retention never drops newer records").
//
// A record whose SavedAt cannot be parsed - which in practice means an
// adopted legacy record (see readRecords), where SavedAt was populated from
// the pre-TD #12 file's own StartedAt and could be empty or in a different
// format - is deliberately kept rather than dropped. Age-based retention
// exists to bound growth from records this store itself knows the save
// time of; it is not a data-quality filter, and silently discarding a
// legacy record because its timestamp cannot be interpreted would destroy
// history the operator did not ask to lose. If pruning genuinely old
// adopted history is wanted, MaxRecords (count-based, timestamp-agnostic)
// is the applicable tool, not MaxAge.
func applyRetention(recs []Record, p RetentionPolicy) []Record {
	out := recs
	if p.MaxAge > 0 {
		cutoff := time.Now().UTC().Add(-p.MaxAge)
		kept := make([]Record, 0, len(out))
		for _, r := range out {
			t, err := time.Parse(time.RFC3339, r.SavedAt)
			// A record with an unparseable/missing timestamp is kept
			// conservatively rather than guessed away - see the doc
			// comment above.
			if err != nil || !t.Before(cutoff) {
				kept = append(kept, r)
			}
		}
		out = kept
	}
	if p.MaxRecords > 0 && len(out) > p.MaxRecords {
		out = out[len(out)-p.MaxRecords:]
	}
	return out
}

// newScanID generates a random, effectively-unique per-record identifier
// (TD #12 requirement #4). It does not need to be content-derived like
// TD #16's payload corpus fingerprint - a scan record's identity is a
// storage-layer concern, not a reproducibility contract - so a random ID is
// sufficient and simpler.
func newScanID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("db: generating scan id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
