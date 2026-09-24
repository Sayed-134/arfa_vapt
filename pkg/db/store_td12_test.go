package db

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"arfa/pkg/models"
)

func sampleResult(target, startedAt string) models.ScanResult {
	return models.ScanResult{
		Target:    target,
		StartedAt: startedAt,
		Findings:  []models.Finding{{ID: "f-" + target + "-" + startedAt, Category: "XSS", Endpoint: target}},
	}
}

// --- Required test 10: storage dir init deterministic ----------------------

func TestOpen_InitializesStorageDirectoryDeterministically(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", "history", "scan_history.json")

	if _, err := Open(path); err != nil {
		t.Fatalf("unexpected error creating nested storage dir: %v", err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || !info.IsDir() {
		t.Fatalf("expected parent directory to exist after Open, err=%v", err)
	}

	// Reopening must not error and must not change the directory.
	if _, err := Open(path); err != nil {
		t.Fatalf("unexpected error on second Open of same path: %v", err)
	}
}

// --- Required test 11: permission/write failure surfaced -------------------

func TestSave_WriteFailureIsSurfacedNotSwallowed(t *testing.T) {
	base := t.TempDir()
	// Create a regular file where a directory is expected, so MkdirAll (and
	// any later write beneath it) fails deterministically regardless of the
	// test process's privilege level (unlike a bare permission-bit test,
	// which a root-run CI container would bypass).
	blocker := filepath.Join(base, "blocked")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "scan_history.json")

	if _, err := Open(path); err == nil {
		t.Fatal("expected Open to surface an error when its storage directory cannot be created")
	}
}

// --- Required test 6: unique scan IDs ---------------------------------------

func TestSave_AssignsUniqueScanIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	for i := 0; i < n; i++ {
		if err := s.Save(sampleResult("http://x", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}

	recs := readBackRecords(t, path)
	if len(recs) != n {
		t.Fatalf("expected %d records, got %d", n, len(recs))
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if r.ID == "" {
			t.Fatal("expected every record to have a non-empty ID")
		}
		if seen[r.ID] {
			t.Fatalf("expected unique scan IDs, found duplicate %q", r.ID)
		}
		seen[r.ID] = true
	}
}

// --- Required tests 3, 4, 5, 13: concurrent writers/readers, atomicity -----

// TestSave_ConcurrentWritersAcrossStoreHandles_NoCorruptionOrLostRecords is
// the direct regression test for TD #12's core bug: two Store handles (the
// closest in-process equivalent of two separate arfa processes pointed at
// the same scan_history.json, since each Store only caches what it last
// read) must not silently clobber each other's Save when writing
// concurrently. Every one of N concurrent Saves, across M independently
// opened Store handles, must be present in the final file - proving the
// lock's read-modify-write-back cycle (see (*Store).Save) actually
// serializes handles, not just goroutines sharing one handle.
func TestSave_ConcurrentWritersAcrossStoreHandles_NoCorruptionOrLostRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}

	const handles = 8
	var wg sync.WaitGroup
	errs := make(chan error, handles)
	for i := 0; i < handles; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A fresh Open() per goroutine simulates a fresh process: its
			// in-memory cache starts from whatever was on disk at that
			// moment, exactly like a second `arfa` invocation would.
			h, err := Open(path)
			if err != nil {
				errs <- err
				return
			}
			if err := h.Save(sampleResult("http://concurrent", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Save failed: %v", err)
	}

	recs := readBackRecords(t, path)
	if len(recs) != handles {
		t.Fatalf("expected %d records (one per concurrent writer, none lost/overwritten), got %d", handles, len(recs))
	}
	ids := map[string]bool{}
	for _, r := range recs {
		if ids[r.ID] {
			t.Fatalf("duplicate record ID %q after concurrent writes", r.ID)
		}
		ids[r.ID] = true
	}
}

// TestSave_ConcurrentReaders_NeverSeeInvalidJSON is the direct regression
// test for TD #12 requirements #2 (atomic writes) and #3's "readers must
// not read partial records": while writers are continuously appending,
// concurrent readers repeatedly read the raw file bytes directly (bypassing
// the Store API, which would hide a transient parse error behind its own
// locking) and must always see either a previous complete JSON array or the
// newest complete one - never a half-written file.
func TestSave_ConcurrentReaders_NeverSeeInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}

	const writers = 6
	const perWriter = 15
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writers: each on its own Store handle, saving repeatedly.
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := Open(path)
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < perWriter; j++ {
				if err := h.Save(sampleResult("http://reader-writer", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
					t.Errorf("Save: %v", err)
				}
			}
		}()
	}

	// Readers: read the raw bytes off disk directly and require them to
	// always parse as a JSON array of Record.
	var readerWG sync.WaitGroup
	readErrs := make(chan error, 100)
	for i := 0; i < 4; i++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b, err := os.ReadFile(path)
				if err != nil {
					if os.IsNotExist(err) {
						continue // store not yet initialized on disk
					}
					readErrs <- err
					continue
				}
				if len(b) == 0 {
					continue
				}
				var recs []Record
				if err := json.Unmarshal(b, &recs); err != nil {
					readErrs <- err
				}
			}
		}()
	}

	wg.Wait()
	close(stop)
	readerWG.Wait()
	close(readErrs)
	for err := range readErrs {
		t.Fatalf("reader observed invalid/partial JSON while writers were active: %v", err)
	}

	recs := readBackRecords(t, path)
	if len(recs) != writers*perWriter {
		t.Fatalf("expected %d total records, got %d", writers*perWriter, len(recs))
	}
}

// --- Required tests 7, 8, 9: retention by count, by age, never drops newer -

// TestRetention_MaxRecordsKeepsOnlyMostRecent is the corrected version of
// this test (TD #12 corrective patch point 3): the original only checked
// that the 3 surviving records happened to be in oldest-to-newest order,
// which a bug that kept the *oldest* 3 instead of the *newest* 3 would
// still have passed. This version captures every saved record's own ID up
// front and asserts, by identity, that retention dropped exactly the 2
// oldest and kept exactly the 3 newest, in their original order.
func TestRetention_MaxRecordsKeepsOnlyMostRecent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	s, err := Open(path, WithMaxRecords(3))
	if err != nil {
		t.Fatal(err)
	}

	const total = 5
	savedIDs := make([]string, 0, total)
	for i := 0; i < total; i++ {
		if err := s.Save(sampleResult("http://x", time.Now().UTC().Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))); err != nil {
			t.Fatal(err)
		}
		recs := readBackRecords(t, path)
		savedIDs = append(savedIDs, recs[len(recs)-1].ID) // the ID just assigned to this Save
	}
	droppedIDs := savedIDs[:total-3]  // the 2 oldest
	wantKeptIDs := savedIDs[total-3:] // the 3 newest, oldest-to-newest

	recs := readBackRecords(t, path)
	if len(recs) != 3 {
		t.Fatalf("expected retention to cap the store at 3 records, got %d", len(recs))
	}

	gotIDs := make([]string, len(recs))
	for i, r := range recs {
		gotIDs[i] = r.ID
	}
	for i, want := range wantKeptIDs {
		if i >= len(gotIDs) || gotIDs[i] != want {
			t.Fatalf("expected the 3 most-recently-saved records to survive in order %v, got %v", wantKeptIDs, gotIDs)
		}
	}
	for _, dropped := range droppedIDs {
		for _, got := range gotIDs {
			if got == dropped {
				t.Fatalf("expected the oldest record %q to be dropped by MaxRecords retention, but it survived in %v", dropped, gotIDs)
			}
		}
	}
}

func TestRetention_MaxAgeDropsOldRecordsKeepsNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")

	// Seed the file directly with one old and one new record, bypassing
	// Save's "now" timestamp so the age boundary is exact and not flaky.
	old := Record{ID: "old", SavedAt: time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339), Result: sampleResult("http://old", "2020-01-01T00:00:00Z")}
	fresh := Record{ID: "fresh", SavedAt: time.Now().UTC().Format(time.RFC3339), Result: sampleResult("http://fresh", "2026-01-01T00:00:00Z")}
	if err := writeRecordsAtomic(path, []Record{old, fresh}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, WithMaxAge(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Saving a third record triggers retention to run over the whole set.
	if err := s.Save(sampleResult("http://third", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatal(err)
	}

	recs := readBackRecords(t, path)
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	if ids["old"] {
		t.Fatal("expected the record older than MaxAge to be dropped by retention")
	}
	if !ids["fresh"] {
		t.Fatal("expected a record newer than MaxAge to be kept by retention")
	}
}

// TestRetention_MaxAgeKeepsRecordWithUnparseableOrEmptySavedAt pins down
// the corrective patch's documented decision (point 4): a record whose
// SavedAt cannot be parsed - the situation for an adopted legacy record
// whose original StartedAt was empty or in an unexpected format - must be
// kept by age-based retention, not silently dropped as if it were simply
// very old.
func TestRetention_MaxAgeKeepsRecordWithUnparseableOrEmptySavedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")

	unparseable := Record{ID: "unparseable", SavedAt: "", Result: sampleResult("http://legacy-empty", "")}
	fresh := Record{ID: "fresh", SavedAt: time.Now().UTC().Format(time.RFC3339), Result: sampleResult("http://fresh", "2026-01-01T00:00:00Z")}
	if err := writeRecordsAtomic(path, []Record{unparseable, fresh}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, WithMaxAge(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Trigger retention by saving one more record.
	if err := s.Save(sampleResult("http://third", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatal(err)
	}

	recs := readBackRecords(t, path)
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	if !ids["unparseable"] {
		t.Fatal("expected a record with an unparseable/empty SavedAt to be kept by MaxAge retention, not dropped")
	}
	if !ids["fresh"] {
		t.Fatal("expected the fresh record to still be present")
	}
}

// --- Stale lock reclamation (crash-recovery path) ---------------------------

// TestSave_ReclaimsLockAbandonedByADeadPID is the direct regression test
// for corrective patch point 1: a .lock file left behind by a process that
// no longer exists, once it is old enough to be outside any legitimate
// in-progress Save (see staleLockAge), must be reclaimed so a later Save
// can proceed - rather than that later Save hanging or timing out forever.
// The dead PID is simulated by spawning and then fully waiting on a real
// child process, so meta.PID is guaranteed to be a PID no longer in use by
// any live process on this system - not a guess or a hardcoded number.
func TestSave_ReclaimsLockAbandonedByADeadPID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}

	deadPID := spawnAndReapProcess(t)

	lockPath := path + ".lock"
	meta := lockMeta{PID: deadPID, CreatedAt: time.Now().UTC().Add(-2 * staleLockAge).Format(time.RFC3339Nano)}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, b, 0644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := s.Save(sampleResult("http://x", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatalf("expected Save to reclaim the abandoned lock and succeed, got: %v", err)
	}
	// Reclamation happens on the very first retry (no sleep needed once the
	// stale lock is recognized), so this must complete far faster than
	// defaultLockTimeout - proving the lock was actively reclaimed, not
	// that Save merely waited out a timeout and happened to find the lock
	// gone for an unrelated reason.
	if elapsed := time.Since(start); elapsed >= defaultLockTimeout {
		t.Fatalf("expected the abandoned lock to be reclaimed promptly, took %s (>= the %s timeout)", elapsed, defaultLockTimeout)
	}

	recs := readBackRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("expected the Save to have succeeded and persisted, got %d records", len(recs))
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected no lock file left behind after Save released it, stat err=%v", err)
	}
}

// TestSave_DoesNotReclaimLockOfALiveProcess confirms the second half of
// the two-signal contract: even once a lock is old enough (past
// staleLockAge), it must NOT be reclaimed while its recorded PID is still
// alive - liveness alone is enough to block reclamation, regardless of
// age. This is exercised as a bounded-timeout failure (rather than an
// indefinite hang) precisely because Save's own lockTimeout is what makes
// "still holding a live lock" an observable, bounded outcome instead of a
// hang - see WithLockTimeout.
func TestSave_DoesNotReclaimLockOfALiveProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}

	lockPath := path + ".lock"
	// This test process's own PID is unambiguously alive.
	meta := lockMeta{PID: os.Getpid(), CreatedAt: time.Now().UTC().Add(-2 * staleLockAge).Format(time.RFC3339Nano)}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(lockPath)

	s, err := Open(path, WithLockTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Save(sampleResult("http://x", time.Now().UTC().Format(time.RFC3339Nano)))
	if err == nil {
		t.Fatal("expected Save to refuse to reclaim a stale-looking but still-live-PID lock, and instead time out")
	}
}

// TestProcessAlive_ConfirmsDeadPIDAndPresumesLiveOnes covers processAlive
// directly: a real, currently-running PID (this test process's own) must
// be reported alive, and a PID known to no longer exist (spawned and
// fully reaped) must be reported dead.
func TestProcessAlive_ConfirmsDeadPIDAndPresumesLiveOnes(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("expected this test process's own PID to be reported alive")
	}
	deadPID := spawnAndReapProcess(t)
	if processAlive(deadPID) {
		t.Fatalf("expected PID %d, spawned and fully reaped, to be reported dead", deadPID)
	}
}

// spawnAndReapProcess starts a minimal child process, waits for it to
// exit, and returns its PID - which the OS is then free to reuse, but
// which no live process currently holds at the moment this returns. Used
// to obtain a genuinely-dead PID for stale-lock tests without guessing a
// number or depending on OS-specific PID allocation behavior.
func spawnAndReapProcess(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to spawn helper process: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("failed to reap helper process: %v", err)
	}
	return pid
}

// --- Required test: legacy (pre-TD #12) history file remains readable ------

func TestOpen_LegacyScanResultArrayIsAdoptedNotRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")

	legacy := []models.ScanResult{sampleResult("http://legacy", "2026-01-01T00:00:00Z")}
	b, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("expected a pre-TD #12 plain ScanResult array to remain readable, got error: %v", err)
	}
	targets := s.Targets()
	if len(targets) != 1 || targets[0].Target != "http://legacy" {
		t.Fatalf("expected the legacy record to be visible via Targets(), got %+v", targets)
	}

	// Saving on top must not error and must result in both the adopted
	// legacy record and the new one being present.
	if err := s.Save(sampleResult("http://new", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatal(err)
	}
	recs := readBackRecords(t, path)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records (1 adopted legacy + 1 new), got %d", len(recs))
	}
	for _, r := range recs {
		if r.ID == "" {
			t.Fatal("expected the adopted legacy record to have been assigned a scan ID")
		}
	}
}

// --- Regression: existing single-handle Save/Targets/CorrelateFindings ----

func TestSave_NoTempFileLeftBehindAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(sampleResult("http://x", time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("expected no leftover temp/lock files after a successful Save, found %q", e.Name())
		}
	}
}

func readBackRecords(t *testing.T, path string) []Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []Record
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatalf("history file is not valid JSON: %v", err)
	}
	return recs
}
