// unreadable_test.go — the canonical NewUnreadableTracker wiring:
// the shared on-disk names are the contract (a literal drift between
// the hygienes would silently split one episode into two), so the
// constructor's persistence + latch-seed wiring is pinned here.

package journalwatch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

func TestNewUnreadableTrackerWiring(t *testing.T) {
	dir := t.TempDir()      // journal storage roots
	stateDir := t.TempDir() // watchdog state dir
	state := hoststate.New(stateDir, "", nil, nil)

	tr := NewUnreadableTracker(state, []string{dir}, 3)

	// The shared streak base name — each owner persists to
	// <base>-<owner>; pin the literal so a rename of the const can't
	// silently split the shared episode.
	if tr.CounterName != UnreadableCounter {
		t.Fatalf("CounterName=%q want the const", tr.CounterName)
	}
	if UnreadableCounter != "consecutive-journal-unreadable" {
		t.Fatalf("shared on-disk name drifted: %q", UnreadableCounter)
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

// TestNewUnreadableTrackerPersistenceAndDefaultNeeded: needed <= 0 →
// DefaultNeeded (5), the streak persists through the wired Counter
// across "restarts" (fresh constructor calls on one state dir) into
// the per-owner file, and recovery exits + resets that file.
func TestNewUnreadableTrackerPersistenceAndDefaultNeeded(t *testing.T) {
	dir := t.TempDir()
	stateDir := t.TempDir()
	state := hoststate.New(stateDir, "", nil, nil)

	a := NewUnreadableTracker(state, []string{dir}, 0)
	for range 4 {
		if a.EnterFrom(OwnerWorkerHygiene, latchdefs.LatchJournalUnreadable) {
			t.Fatal("failure entered before DefaultNeeded")
		}
	}

	// "Restart": a freshly wired tracker must resume the on-disk
	// streak, not re-arm at zero.
	b := NewUnreadableTracker(state, []string{dir}, 0)
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
