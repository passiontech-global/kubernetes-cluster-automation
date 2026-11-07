// w13_test.go — Wave-13 controller-hygiene tests: the W13 Gap#2
// single-controller streak multiplier (the W13-CP1 terminated-
// watchers mirror moved to apiserver/, the W13-ST2 etcd snapshot
// verifier to etcd/).
package controllerhygiene

import (
	"testing"
)

// --- W13 Gap#2: single-controller streak multiplier ---

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
