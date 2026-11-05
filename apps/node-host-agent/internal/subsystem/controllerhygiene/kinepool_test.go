// kinepool_test.go — kine postgres connection-pool runaway guard.

package controllerhygiene

import (
	"context"
	"strconv"
	"syscall"
	"testing"
)

// --- Guard b: kine pool ---

func TestKinePoolSpiral(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 80; i++ {
		e.mkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	for i := 0; i < 3; i++ { // KinePoolCycles=3
		e.h.Cycle(context.Background())
	}
	if !e.hasState(stateKinePoolRunaway) {
		t.Fatal("kine-pool-runaway state missing")
	}
	if len(e.kills) != 1 || e.kills[0].pid != 1001 || e.kills[0].sig != syscall.SIGTERM {
		t.Fatalf("expected SIGTERM on kine pid 1001, got %v", e.kills)
	}
	// Cooldown: still spiralling but no second kill.
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 {
		t.Fatal("cooldown did not suppress the second kill")
	}
}

func TestKinePoolHealthy(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 10; i++ {
		e.mkSock(t, 1001, 100+i, strconv.Itoa(60000+i), 6432)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("healthy conn count killed kine")
	}
	if e.hasState(stateKinePoolRunaway) {
		t.Fatal("runaway latched on healthy pool")
	}
}
