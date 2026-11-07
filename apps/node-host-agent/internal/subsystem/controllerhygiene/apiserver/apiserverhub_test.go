// apiserverhub_test.go — apiserver-hub wedge/dead-fallback guards, the kine TTL tail, and suspect-log dedupe.

package apiserver_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

	"context"
	"path/filepath"
	"testing"
)

// --- Guard a: wedge detection ---

func TestGapWedgePeerFreshRestarts(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	// rv_now - rv_cache > 10000; peer close to head => fresh.
	e.SetRV(self, false, 20000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 19900, true)
	e.H.Cycle(context.Background()) // gn=1
	e.H.Cycle(context.Background()) // gn=2 => wedge confirmed
	if !e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("state-apiserver-cache-wedged missing")
	}
	if e.RstN() != 1 || e.RstAt(0) != "k0scontroller.service" {
		t.Fatalf("expected 1 restart, got %d", e.RstN())
	}
	// Rate budget spent.
	if h := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateRestart)); h == 0 {
		t.Fatal("last-sig13-restart budget not spent")
	}
}

func TestGapWedgePeerStaleHeld(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 90000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 4000, true) // peer cache far behind too
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("restart happened while peer stale and solo cycles short")
	}
	if !e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("wedge state missing")
	}
}

func TestFrozenWedgeSoloAfterCycles(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	e.H.Cfg.Hub.PeerAPI = "" // single-hub => always first
	// spof-streak: pin a 2-controller topology so the solo-restart
	// mechanics under test are not masked by the SPOF doubled
	// streak (TestSPOFStreakCycles owns that contract).
	e.H.Cfg.TotalControllers = 2
	rvN := int64(100)
	// rv_cache frozen at 50 while rv_now grows — the first cycle
	// only seeds last-rvc, so FrozenCycles=2 trips on cycle 3.
	for i := 0; i < 3; i++ {
		e.SetRV(self, true, 50, true)
		e.SetRV(self, false, rvN, true)
		rvN += 10
		e.H.Cycle(context.Background())
	}
	if !e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("frozen wedge not detected after FrozenCycles")
	}
	// Solo path needs SoloCycles gap-counter (each wedged cycle
	// increments) — keep cycling until restart.
	for i := 0; i < 10 && e.RstN() == 0; i++ {
		e.SetRV(self, false, rvN, true)
		rvN += 10
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("expected solo restart, got %d", e.RstN())
	}
}

func TestIdleClusterNoFrozen(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	// rv_now == rv_cache — standing still is not wedge evidence.
	for i := 0; i < 4; i++ {
		e.SetRV(self, true, 70, true)
		e.SetRV(self, false, 70, true)
		e.H.Cycle(context.Background())
	}
	if e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("idle cluster latched as wedged")
	}
	if e.RstN() != 0 {
		t.Fatal("idle cluster triggered restart")
	}
}

func TestRecoveryClearsWedge(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 90000, true)
	e.SetRV(self, true, 1000, true)
	e.SetRV(peer, true, 89900, true)
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("precondition: wedge not latched")
	}
	// Cache catches up.
	e.SetRV(self, true, 89500, true)
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("wedge state not cleared on recovery")
	}
}

func TestDeadFallbackKineOK(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Hub.PeerAPI = "" // single hub
	// spof-streak: pin a 2-controller topology — the dead-fallback
	// streak would otherwise double before the restart.
	e.H.Cfg.TotalControllers = 2
	e.H.Cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.Journal = "x required revision has been compacted\n" // cache_errs > 0
	// Both queries dead, DB healthy → dead-fallback after SoloCycles.
	for i := 0; i < 9 && e.RstN() == 0; i++ {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("dead-fallback restart missing: %d", e.RstN())
	}
	if e.HasState(cdeps.StateKineUnreachable) {
		t.Fatal("kine-backend-unreachable latched despite healthy DB")
	}
}

func TestDeadFallbackKineDead(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.Journal = "x required revision has been compacted\n"
	e.PgOK = false // DB broken → apiserver restart is useless
	for i := 0; i < 12; i++ {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("restart ran while DB dead")
	}
	if !e.HasState(cdeps.StateKineUnreachable) {
		t.Fatal("kine-backend-unreachable missing")
	}
}

func TestSecondHubNeverSolo(t *testing.T) {
	e := fixture(t)
	// Self sorts AFTER peer → second hub.
	e.H.Cfg.Hub.SelfAPI = "10.0.0.9:6443"
	e.H.Cfg.Hub.PeerAPI = "10.0.0.2:6443"
	self := "127.0.0.1:6443"
	e.SetRV(self, false, 90000, true)
	e.SetRV(self, true, 5000, true)
	// peer unreachable → peer_note=unreachable, not fresh.
	for i := 0; i < 12; i++ {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("second hub restarted without fresh peer")
	}
}
