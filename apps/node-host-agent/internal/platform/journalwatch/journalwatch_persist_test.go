// journalwatch_persist_test.go — the on-disk streak persistence:
// restart resume across Tracker instances sharing one counter file,
// file reset on a good read, LatchedSeed restoring the latch, and
// the unwired/half-wired RAM-only fallbacks.
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
const persistCounterName = "consecutive-journal-unreadable"

// TestCounterResumeAcrossRestart: an agent restart mid-episode must
// resume the persisted streak — the second Tracker seeds from the
// consecutive-* file and the resumed Nth failure enters, not the
// Nth of a fresh streak.
func TestCounterResumeAcrossRestart(t *testing.T) {
	dir := t.TempDir()      // journal storage dir
	stateDir := t.TempDir() // watchdog state dir
	store := hoststate.New(stateDir, "", nil, nil)

	tr1 := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	for i := 1; i <= 2; i++ {
		if enter, exit := tr1.NoteRead(false); enter || exit {
			t.Fatalf("first instance fail %d: enter=%v exit=%v, want neither",
				i, enter, exit)
		}
	}
	if tr1.Fails() != 2 {
		t.Fatalf("first instance fails=%d want 2", tr1.Fails())
	}

	// "Restart": a fresh Tracker on the same state dir. Accessors
	// stay pure — no lazy seed before the first NoteRead.
	tr2 := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	if f := tr2.Fails(); f != 0 {
		t.Fatalf("Fails() before first NoteRead = %d want 0 (pure accessor)", f)
	}
	enter, exit := tr2.NoteRead(false)
	if !enter || exit {
		t.Fatalf("resumed 3rd failure: enter=%v exit=%v, want enter", enter, exit)
	}
	if tr2.Fails() != 3 {
		t.Fatalf("resumed fails=%d want 3", tr2.Fails())
	}
}

// TestCounterSharedAcrossTrackers: two live trackers on one counter
// file converge on the shared count — the deliberate shared-latch
// semantics of controllerhygiene + workerhygiene owning one
// state-journal-unreadable episode.
func TestCounterSharedAcrossTrackers(t *testing.T) {
	dir := t.TempDir()
	store := hoststate.New(t.TempDir(), "", nil, nil)
	mk := func() *Tracker {
		return &Tracker{Needed: 3, Dirs: []string{dir},
			Counter: store, CounterName: persistCounterName}
	}
	a, b := mk(), mk()
	a.NoteRead(false) // file 1, a.fails 1
	b.NoteRead(false) // file 2, b.fails 2 — sibling's fail counted
	if enter, _ := b.NoteRead(false); !enter {
		t.Fatal("shared streak: b's 3rd file increment should enter")
	}
}

// TestGoodReadResetsCounterFile: a good read zeroes the RAM streak
// AND removes the file, so a restarted tracker re-arms from zero.
func TestGoodReadResetsCounterFile(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	store := hoststate.New(stateDir, "", nil, nil)

	tr := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	tr.NoteRead(false)
	tr.NoteRead(false)
	tr.NoteRead(true) // blip recovered — streak + file must reset
	if _, err := os.Stat(filepath.Join(stateDir, persistCounterName)); !os.IsNotExist(err) {
		t.Fatalf("counter file should be removed on a good read, stat err=%v", err)
	}
	// A post-restart tracker must not inherit the stale streak.
	tr2 := &Tracker{Needed: 3, Dirs: []string{dir},
		Counter: store, CounterName: persistCounterName}
	tr2.NoteRead(false)
	tr2.NoteRead(false)
	if enter, _ := tr2.NoteRead(false); !enter {
		t.Fatal("fresh streak after reset should need the full budget")
	}
}

// TestLatchedSeedResumesLatched: a restart while the latch file
// exists resumes latched — the first healthy read then returns exit
// so the caller clears the stale state-* file instead of it
// lingering to the janitor's 24h reap.
func TestLatchedSeedResumesLatched(t *testing.T) {
	dir := t.TempDir()
	latchHeld := true
	tr := &Tracker{Needed: 3, Dirs: []string{dir},
		LatchedSeed: func() bool { return latchHeld }}

	// Accessors stay pure: no seed consumed before the first verdict.
	if tr.Latched() {
		t.Fatal("Latched() before first NoteRead should report false (pure accessor)")
	}
	// A failing read while seeded-latched re-fires nothing.
	if enter, exit := tr.NoteRead(false); enter || exit {
		t.Fatalf("seeded latched + fail: enter=%v exit=%v, want neither", enter, exit)
	}
	if !tr.Latched() {
		t.Fatal("seeded latch should be held after the first NoteRead")
	}
	// The first healthy read exits — the caller's STATE-EXIT edge.
	enter, exit := tr.NoteRead(true)
	if enter || !exit {
		t.Fatalf("seeded latched + healthy read: enter=%v exit=%v, want exit",
			enter, exit)
	}
}

// TestNoCounterWiredStaysRAMOnly: zero-value persistence fields keep
// the tracker pure-RAM — literal-constructed fixtures unchanged.
func TestNoCounterWiredStaysRAMOnly(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 2, Dirs: []string{dir}}
	tr.NoteRead(false)
	if enter, _ := tr.NoteRead(false); !enter {
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
	tr.NoteRead(false)
	if enter, _ := tr.NoteRead(false); !enter {
		t.Fatal("RAM fallback should still enter on a full streak")
	}
	// Nothing may have been written under the bare name in CWD.
	if _, err := os.Stat(persistCounterName); !os.IsNotExist(err) {
		t.Fatalf("bare-named counter file leaked into CWD, stat err=%v", err)
	}
}
