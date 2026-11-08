// kinepool_test.go — kine postgres connection-pool runaway guard.

package storelocal_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

	"context"
	"strconv"
	"syscall"
	"testing"
)

// --- Guard b: kine pool ---

func TestKinePoolSpiral(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 80; i++ {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	for i := 0; i < 3; i++ { // KinePoolCycles=3
		e.H.Cycle(context.Background())
	}
	if !e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("kine-pool-runaway state missing")
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 1001 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("expected SIGTERM on kine pid 1001, got %v", e.Kills)
	}
	// Cooldown: still spiralling but no second kill.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 {
		t.Fatal("cooldown did not suppress the second kill")
	}
}

func TestKinePoolHealthy(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 10; i++ {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(60000+i), 6432)
	}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatal("healthy conn count killed kine")
	}
	if e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("runaway latched on healthy pool")
	}
}
