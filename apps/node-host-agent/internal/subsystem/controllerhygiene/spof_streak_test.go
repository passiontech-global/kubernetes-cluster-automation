// spof_streak_test.go — the spof-streak single-controller streak
// multiplier tests (the relist-storm terminated-watchers mirror moved
// to apiserver/, the backup-health etcd snapshot verifier to etcd/).
package controllerhygiene

import (
	"testing"
)

// --- spof-streak: single-controller streak multiplier ---

func TestSPOFStreakCycles(t *testing.T) {
	e := fixture(t)
	// Fixture wires a peer → not single-controller, no doubling.
	if got := e.H.Deps.StreakCycles(4); got != 4 {
		t.Fatalf("peer set: streakCycles=%d want 4", got)
	}
	// Explicit topology override wins over the PeerAPI heuristic.
	e.H.Cfg.TotalControllers = 3
	if got := e.H.Deps.StreakCycles(4); got != 4 {
		t.Fatalf("TotalControllers=3: streakCycles=%d want 4", got)
	}
	e.H.Cfg.TotalControllers = 1
	if got := e.H.Deps.StreakCycles(4); got != 8 {
		t.Fatalf("TotalControllers=1: streakCycles=%d want 8", got)
	}
	// Auto: no peer configured → single-controller → doubled.
	e.H.Cfg.TotalControllers = 0
	e.H.Cfg.Hub.PeerAPI = ""
	if !e.H.Deps.SingleController() {
		t.Fatal("PeerAPI empty but singleController=false")
	}
	if got := e.H.Deps.StreakCycles(5); got != 10 {
		t.Fatalf("single-controller streakCycles=%d want 10", got)
	}
}
