// unreadable_test.go — the canonical NewUnreadableTrackerForOwner
// wiring: the shared on-disk names are the contract (a literal drift
// between the hygienes would silently split one episode into two),
// so the constructor's persistence + latch-seed + owner-binding
// wiring is pinned here.

package journalwatch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

func TestNewUnreadableTrackerForOwnerWiring(t *testing.T) {
	dir := t.TempDir()      // journal storage roots
	stateDir := t.TempDir() // watchdog state dir
	state := hoststate.New(stateDir, "", nil, nil)

	tr := NewUnreadableTrackerForOwner(state, []string{dir}, 3,
		OwnerWorkerHygiene)

	// The shared streak base name — each owner persists to
	// <base>-<owner>; pin the literal so a rename of the const can't
	// silently split the shared episode.
	if tr.CounterName != UnreadableCounter {
		t.Fatalf("CounterName=%q want the const", tr.CounterName)
	}
	if UnreadableCounter != "consecutive-journal-unreadable" {
		t.Fatalf("shared on-disk name drifted: %q", UnreadableCounter)
	}
	if tr.Owner != OwnerWorkerHygiene {
		t.Fatalf("Owner=%q want the wired producer id", tr.Owner)
	}
	if tr.Counter != state {
		t.Fatal("Counter must be the wired state store")
	}
	if len(tr.Dirs) != 1 || tr.Dirs[0] != dir {
		t.Fatalf("Dirs=%v want the journal roots passthrough", tr.Dirs)
	}
	if tr.Needed != 3 {
		t.Fatalf("Needed=%d want the explicit budget 3", tr.Needed)
	}

	// LatchedSeed is bound to the REAL state-journal-unreadable latch
	// file — latched iff it exists.
	if tr.LatchedSeed() {
		t.Fatal("seed true without the latch file")
	}
	state.Enter(latchdefs.LatchJournalUnreadable, "")
	if !tr.LatchedSeed() {
		t.Fatal("seed must follow the existing latch file")
	}
	state.Exit(latchdefs.LatchJournalUnreadable, nil)
	if tr.LatchedSeed() {
		t.Fatal("seed must clear with the latch file")
	}
}

// TestNewUnreadableTrackerForOwnerRequired: the owner-less form is
// no longer producible — an empty owner must panic at construction
// (a wiring error: it would collapse both hygienes' streaks onto one
// counter and defeat the owner-scoped EnterFrom/ExitFrom in
// wdeps/cdeps).
func TestNewUnreadableTrackerForOwnerRequired(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("empty owner must be refused at construction")
		}
	}()
	_ = NewUnreadableTrackerForOwner(
		hoststate.New(t.TempDir(), "", nil, nil), nil, 0, "")
}

// TestNewUnreadableTrackerOwnerIsolation: two trackers bound to
// DIFFERENT owners over the SAME store isolate their streaks —
// workerhygiene's failures never inflate or reset
// controllerhygiene's count, and neither tracker latches off the
// other's streak. This is the regression the owner binding exists
// for: the pre-fix wiring passed owner="" so both hygienes shared
// one streak file and one latched state.
func TestNewUnreadableTrackerOwnerIsolation(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	state := hoststate.New(stateDir, "", nil, nil)

	w := NewUnreadableTrackerForOwner(state, []string{dir}, 3,
		OwnerWorkerHygiene)
	c := NewUnreadableTrackerForOwner(state, []string{dir}, 3,
		OwnerControllerHygiene)

	// Worker fails twice — below its own Needed.
	for range 2 {
		if w.EnterFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
			t.Fatal("worker entered before its Needed budget")
		}
	}
	// The failures landed in the WORKER's file only.
	if got := state.Counter(UnreadableCounter + "-" + OwnerWorkerHygiene); got != 2 {
		t.Fatalf("worker streak file = %d want 2", got)
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		UnreadableCounter+"-"+OwnerControllerHygiene)); !os.IsNotExist(err) {
		t.Fatalf("controller streak file must not exist, stat err=%v", err)
	}
	// Controller's view is untouched: zero streak, not latched.
	if c.Fails() != 0 || c.Latched() {
		t.Fatalf("controller polluted by worker's streak: fails=%d latched=%v",
			c.Fails(), c.Latched())
	}

	// A healthy read on the controller resets only ITS (empty)
	// streak — the worker's persisted count survives.
	if c.ExitFrom(OwnerControllerHygiene, latchdefs.LatchJournalUnreadable) {
		t.Fatal("controller was never latched — exit edge must be false")
	}
	if got := state.Counter(UnreadableCounter + "-" + OwnerWorkerHygiene); got != 2 {
		t.Fatalf("controller's healthy read reset the worker's streak: %d", got)
	}

	// Worker reaches its Needed → IT latches; the controller's
	// tracker still does not.
	if !w.EnterFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
		t.Fatal("worker's 3rd failure must enter")
	}
	if c.Latched() {
		t.Fatal("controller latched off the worker's streak")
	}
	if w.Latched() != true {
		t.Fatal("worker tracker must be latched after its Needed streak")
	}
	// The worker's recovery clears only the worker's file.
	if !w.ExitFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
		t.Fatal("worker recovery must report the exit edge")
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		UnreadableCounter+"-"+OwnerWorkerHygiene)); !os.IsNotExist(err) {
		t.Fatalf("worker streak file not removed on recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		UnreadableCounter+"-"+OwnerControllerHygiene)); !os.IsNotExist(err) {
		t.Fatalf("controller streak file appeared: %v", err)
	}
}

// TestNewUnreadableTrackerPersistenceAndDefaultNeeded: needed <= 0 →
// DefaultNeeded (5), the streak persists through the wired Counter
// across "restarts" (fresh constructor calls on one state dir) into
// the per-owner file, and recovery exits + resets that file.
func TestNewUnreadableTrackerPersistenceAndDefaultNeeded(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	state := hoststate.New(stateDir, "", nil, nil)

	a := NewUnreadableTrackerForOwner(state, []string{dir}, 0,
		OwnerWorkerHygiene)
	for range 4 {
		if a.EnterFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
			t.Fatal("failure entered before DefaultNeeded")
		}
	}

	// "Restart": a freshly wired tracker must resume the on-disk
	// streak, not re-arm at zero.
	b := NewUnreadableTrackerForOwner(state, []string{dir}, 0,
		OwnerWorkerHygiene)
	if !b.EnterFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
		t.Fatal("5th (persisted) failure must enter")
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		UnreadableCounter+"-"+OwnerWorkerHygiene)); err != nil {
		t.Fatalf("per-owner streak file missing: %v", err)
	}

	// A good read while latched exits and resets the owner's file.
	if !b.ExitFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
		t.Fatal("good read while latched must report the exit edge")
	}
	if _, err := os.Stat(filepath.Join(stateDir,
		UnreadableCounter+"-"+OwnerWorkerHygiene)); !os.IsNotExist(err) {
		t.Fatalf("good read must remove the streak file, stat err=%v", err)
	}
}
