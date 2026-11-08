// journalwatch_persist_test.go — the on-disk streak persistence:
// restart resume across Tracker instances sharing one per-owner
// counter file, per-owner file isolation, file reset on a good read,
// the legacy shared counter file sweep, LatchedSeed restoring the
// latch, and the unwired/half-wired RAM-only fallbacks.
package journalwatch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// persistCounterName deliberately stays a literal (not
// UnreadableCounter): it pins the on-disk filename contract, so a
// contract-breaking rename of the exported const trips these tests.
// The per-owner files carry the -<owner> suffix.
const (
	persistCounterName = "consecutive-journal-unreadable"
	persistOwner       = "workerhygiene"
)

// TestCounterResumeAcrossRestart: an agent restart mid-episode must
// resume the persisted streak — the second Tracker seeds from the
// per-owner consecutive-* file and the resumed Nth failure enters,
// not the Nth of a fresh streak.
func TestCounterResumeAcrossRestart(t *testing.T) {
	dir := t.TempDir()      // journal storage dir
	stateDir := t.TempDir() // watchdog state dir
	store := hoststate.New(stateDir, "", nil, nil)

	tr1 := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	for range 2 {
		if tr1.EnterFrom(persistOwner, "journal-unreadable") {
			t.Fatal("first instance entered before the budget")
		}
	}
	if tr1.Fails() != 2 {
		t.Fatalf("first instance fails=%d want 2", tr1.Fails())
	}
	streak := filepath.Join(stateDir, persistCounterName+"-"+persistOwner)
	if _, err := os.Stat(streak); err != nil {
		t.Fatalf("per-owner streak file missing: %v", err)
	}

	// "Restart": a fresh Tracker on the same state dir. Accessors
	// stay pure — no lazy seed before the first EnterFrom.
	tr2 := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	if f := tr2.Fails(); f != 0 {
		t.Fatalf("Fails() before first EnterFrom = %d want 0 (pure accessor)", f)
	}
	if !tr2.EnterFrom(persistOwner, "journal-unreadable") {
		t.Fatal("resumed 3rd failure must enter")
	}
	if tr2.Fails() != 3 {
		t.Fatalf("resumed fails=%d want 3", tr2.Fails())
	}
}

// TestOwnerCounterFilesAreSeparate: the two producers keep their own
// streak files — one owner's recovery resets ITS file only, never the
// sibling's persisted count (the whole point of the owner scoping).
func TestOwnerCounterFilesAreSeparate(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	store := hoststate.New(stateDir, "", nil, nil)

	mk := func() *Tracker {
		return &Tracker{Needed: 3, Dirs: []string{dir},
			Counter: store, CounterName: persistCounterName}
	}
	w := mk()
	for range 2 {
		w.EnterFrom(OwnerWorkerHygiene, "journal-unreadable")
	}
	c := mk()
	for range 2 {
		c.EnterFrom(OwnerControllerHygiene, "journal-unreadable")
	}

	// Worker recovers — only worker's file goes; controller's streak
	// survives on disk AND on a freshly seeded tracker.
	if w.ExitFrom(OwnerWorkerHygiene, "journal-unreadable") {
		t.Fatal("worker was not latched — no exit edge expected")
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		persistCounterName+"-"+OwnerWorkerHygiene)); !os.IsNotExist(err) {
		t.Fatal("worker streak file should be removed on recovery")
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		persistCounterName+"-"+OwnerControllerHygiene)); err != nil {
		t.Fatal("controller streak file must survive the sibling's recovery")
	}
	c2 := mk()
	if !c2.EnterFrom(OwnerControllerHygiene, "journal-unreadable") {
		t.Fatal("controller's persisted streak must resume (3rd failure enters)")
	}
}

// TestGoodReadResetsCounterFile: a good read zeroes the RAM streak
// AND removes the per-owner file, so a restarted tracker re-arms
// from zero.
func TestGoodReadResetsCounterFile(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	store := hoststate.New(stateDir, "", nil, nil)

	tr := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	tr.EnterFrom(persistOwner, "journal-unreadable")
	tr.EnterFrom(persistOwner, "journal-unreadable")
	tr.ExitFrom(persistOwner, "journal-unreadable") // blip recovered
	if _, err := os.Stat(filepath.Join(stateDir,
		persistCounterName+"-"+persistOwner)); !os.IsNotExist(err) {
		t.Fatalf("counter file should be removed on a good read, stat err=%v", err)
	}
	// A post-restart tracker must not inherit the stale streak.
	tr2 := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	tr2.EnterFrom(persistOwner, "journal-unreadable")
	tr2.EnterFrom(persistOwner, "journal-unreadable")
	if !tr2.EnterFrom(persistOwner, "journal-unreadable") {
		t.Fatal("fresh streak after reset should need the full budget")
	}
}

// TestLegacySharedCounterSwept: the pre-owner-scoping build kept ONE
// shared consecutive-journal-unreadable file — dead state after the
// split, swept once at seed so no orphan lingers in the dir.
func TestLegacySharedCounterSwept(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	store := hoststate.New(stateDir, "", nil, nil)
	legacy := filepath.Join(stateDir, persistCounterName)
	if err := os.WriteFile(legacy, []byte("3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tr := &Tracker{Needed: 5, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	tr.EnterFrom(persistOwner, "journal-unreadable")

	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy shared counter file not swept: %v", err)
	}
	// The seeded streak reads the PER-OWNER file (absent → 1), never
	// the legacy count.
	if tr.Fails() != 1 {
		t.Fatalf("fails=%d want 1 (legacy count must not bleed in)", tr.Fails())
	}
}

// TestLatchedSeedResumesLatched: a restart while the latch file
// exists resumes latched — the first healthy read then reports the
// exit edge so the caller releases through Store.ExitFrom and clears
// the stale state-* file instead of it lingering to the janitor's
// 24h reap.
func TestLatchedSeedResumesLatched(t *testing.T) {
	dir := t.TempDir()
	latchHeld := true
	tr := &Tracker{Needed: 3, Dirs: []string{dir},
		LatchedSeed: func() bool { return latchHeld }}

	// Accessors stay pure: no seed consumed before the first verdict.
	if tr.Latched() {
		t.Fatal("Latched() before first EnterFrom should report false (pure accessor)")
	}
	// A failing read while seeded-latched re-fires nothing.
	if tr.EnterFrom("workerhygiene", "journal-unreadable") {
		t.Fatal("seeded latched + fail must not re-fire the enter edge")
	}
	if !tr.Latched() {
		t.Fatal("seeded latch should be held after the first EnterFrom")
	}
	// The first healthy read exits — the caller's store release.
	if !tr.ExitFrom("workerhygiene", "journal-unreadable") {
		t.Fatal("seeded latched + healthy read must report the exit edge")
	}
}

// TestNoCounterWiredStaysRAMOnly: zero-value persistence fields keep
// the tracker pure-RAM — literal-constructed fixtures unchanged.
func TestNoCounterWiredStaysRAMOnly(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 2, Dirs: []string{dir}}
	tr.EnterFrom("workerhygiene", "journal-unreadable")
	if !tr.EnterFrom("workerhygiene", "journal-unreadable") {
		t.Fatal("RAM-only tracker should still enter on a full streak")
	}
}

// TestEmptyCounterDirNeverWritesCWD: a "" Store.Dir must disable the
// file half entirely — bare filenames in the process CWD are worse
// than no persistence.
func TestEmptyCounterDirNeverWritesCWD(t *testing.T) {
	dir := t.TempDir()
	store := hoststate.New("", "", nil, nil) // Dir "" — the bare-name hazard
	tr := &Tracker{Needed: 2, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	tr.EnterFrom("workerhygiene", "journal-unreadable")
	if !tr.EnterFrom("workerhygiene", "journal-unreadable") {
		t.Fatal("RAM fallback should still enter on a full streak")
	}
	// Nothing may have been written under the bare names in CWD.
	for _, name := range []string{
		persistCounterName,
		persistCounterName + "-" + persistOwner,
	} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("bare-named counter file leaked into CWD: %s (err=%v)", name, err)
		}
	}
}
