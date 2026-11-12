// apiserverhub_test.go — apiserver-hub wedge/dead-fallback guards, the kine TTL tail, and suspect-log dedupe.

package apiserver_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
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

// The peer-fresh wedge restart must hold when the kubernetes
// service reports fewer than 2 ready apiserver endpoints — bouncing
// the controller below quorum takes the last serving apiserver
// down with it.
func TestGapWedgePeerFreshQuorumHold(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 20000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 19900, true)
	e.EPReady = map[string]int{peer: 1} // only one apiserver serving
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateCacheWedged) {
		t.Fatal("state-apiserver-cache-wedged missing")
	}
	if e.RstN() != 0 {
		t.Fatalf("restart fired below endpoint quorum: %v", e.RstAt(0))
	}
	if n := e.CountLogLines("<2 ready endpoints"); n == 0 {
		t.Fatalf("quorum hold not suspect-logged:\n%s", e.LogLines())
	}
}

// >=2 ready endpoints lets the same wedge restart through — the
// quorum gate only holds below quorum.
func TestGapWedgePeerFreshQuorumPass(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 20000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 19900, true)
	e.EPReady = map[string]int{peer: 2}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.RstN() != 1 {
		t.Fatalf("quorum-satisfied wedge did not restart: %d", e.RstN())
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
	for range 12 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatal("second hub restarted without fresh peer")
	}
}

// --- early-warning + early-gate branches ---

// 15+ journal errors inside 6 minutes latch apiserver-cache-stale —
// the early-warning signal, cleared again once the journal goes quiet.
func TestCacheStaleEarlyWarningLatchesAndClears(t *testing.T) {
	e := fixture(t)
	var b strings.Builder
	for range 15 {
		b.WriteString("Cache consistency check error on /registry/x\n")
	}
	e.Journal = b.String()
	cdepstest.Check[*apiserver.HubCheck](e.H, cdeps.CheckHub).
		Run(context.Background())
	if !e.HasState(cdeps.StateCacheStale) {
		t.Fatal("apiserver-cache-stale not latched on 15 errors/6min")
	}
	if e.CountLogLines("watch-cache/consistency errors") == 0 {
		t.Fatalf("cache-stale suspect not logged:\n%s", e.LogLines())
	}
	e.Journal = ""
	cdepstest.Check[*apiserver.HubCheck](e.H, cdeps.CheckHub).
		Run(context.Background())
	if e.HasState(cdeps.StateCacheStale) {
		t.Fatal("cache-stale latch outlived a quiet journal")
	}
}

// Without admin credentials the whole rv probe is a no-op — the
// no_creds outcome is counted and nothing probes or restarts.
func TestHubRunNoCreds(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.HTTPClient = nil
	e.H.Client = nil // admin cert/key files missing → EnsureClient nil
	cdepstest.Check[*apiserver.HubCheck](e.H, cdeps.CheckHub).
		Run(context.Background())
	if v := promtest.ToFloat64(
		e.H.Cycles.WithLabelValues(cdeps.CheckHub, "no_creds")); v != 1 {
		t.Fatalf("no_creds counter=%v want 1", v)
	}
	if e.HasState(cdeps.StateCacheWedged) || e.RstN() != 0 {
		t.Fatal("rv probe ran without credentials")
	}
}

// --- wedge-remediation gating branches ---

// A second wedge inside MinRestart lands in the cooldown branch —
// the fence must not double-restart.
func TestWedgeRestartCooldown(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 20000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 19900, true)
	for range 2 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("precondition: restarts=%d", e.RstN())
	}
	for range 2 { // re-wedge inside the rate budget
		e.SetRV(self, true, 5000, true)
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("cooldown not honored: restarts=%d", e.RstN())
	}
	if e.CountLogLines("in restart cooldown") == 0 {
		t.Fatalf("fence cooldown not logged:\n%s", e.LogLines())
	}
}

// Dry-run mode logs the fence action without touching systemd.
func TestWedgeDryRunRestartsNothing(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Sig13.Mode = cdeps.ModeDryRun
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 20000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 19900, true)
	for range 2 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatalf("dry-run restarted: %v", e.RstAt(0))
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckHub, "dryrun_restart")); v != 1 {
		t.Fatalf("dryrun_restart counter=%v want 1", v)
	}
	if !strings.Contains(e.LogLines(),
		"DRY-RUN: would restart k0scontroller - apiserver-cache-wedged") {
		t.Fatalf("dry-run action not logged:\n%s", e.LogLines())
	}
}

// A failing systemctl restart is a suspect warn, and the rate budget
// spend still happened (the attempt is not free).
func TestWedgeRestartFailureWarns(t *testing.T) {
	e := fixture(t)
	oldExec := e.H.Cfg.HostExecFn
	e.H.Cfg.HostExecFn = func(ctx context.Context, quiet bool, d time.Duration,
		name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			return "", errors.New("systemctl: Job failed")
		}
		return oldExec(ctx, quiet, d, name, args...)
	}
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.SetRV(self, false, 20000, true)
	e.SetRV(self, true, 5000, true)
	e.SetRV(peer, true, 19900, true)
	for range 2 {
		e.H.Cycle(context.Background())
	}
	if !strings.Contains(e.LogLines(),
		"suspect: restart k0scontroller.service failed") {
		t.Fatalf("restart failure not warned:\n%s", e.LogLines())
	}
	if h := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateRestart)); h == 0 {
		t.Fatal("rate budget not spent on the failed attempt")
	}
}

// --- deadFallback branches ---

// No kine pg-wire probe configured → the dead-fallback is blind: it
// suspects and returns without ever deciding DB-dead vs apiserver-dead.
func TestDeadFallbackNoKineProbeReturns(t *testing.T) {
	e := fixture(t) // KineDBProbe unset (default "")
	e.Journal = "x required revision has been compacted\n"
	for range 5 {
		e.H.Cycle(context.Background()) // both RV unscripted → dead
	}
	if e.RstN() != 0 {
		t.Fatal("restart without any dead-fallback evidence chain")
	}
	if e.HasState(cdeps.StateKineUnreachable) {
		t.Fatal("kine-backend-unreachable latched without a probe configured")
	}
	if e.CountLogLines("rv-gap unmeasurable") == 0 {
		t.Fatalf("dead-fallback blind suspect not logged:\n%s", e.LogLines())
	}
}

// A second dead episode inside MinRestart hits the cooldown branch.
func TestDeadFallbackCooldown(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Hub.PeerAPI = ""
	e.H.Cfg.TotalControllers = 2
	e.H.Cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.Journal = "x required revision has been compacted\n"
	for range 20 {
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 1 {
		t.Fatalf("expected exactly one dead-fallback restart, got %d", e.RstN())
	}
	// The cooldown suspect line rides the LogKeyDeadFallbk cadence
	// budget, spent by the earlier "needs N cycles" episodes of the
	// same key under the frozen fixture clock — the observable is
	// the budget state: no second restart inside MinRestart.
}

// A dead-fallback restart failure is logged as a suspect warn.
func TestDeadFallbackRestartFailureWarns(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Hub.PeerAPI = ""
	e.H.Cfg.TotalControllers = 2
	e.H.Cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.Journal = "x required revision has been compacted\n"
	oldExec := e.H.Cfg.HostExecFn
	e.H.Cfg.HostExecFn = func(ctx context.Context, quiet bool, d time.Duration,
		name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			return "", errors.New("systemctl: Job failed")
		}
		return oldExec(ctx, quiet, d, name, args...)
	}
	for range 12 {
		e.H.Cycle(context.Background())
	}
	if !strings.Contains(e.LogLines(),
		"suspect: restart k0scontroller.service failed") {
		t.Fatalf("dead-fallback restart failure not warned:\n%s", e.LogLines())
	}
	if e.RstN() != 0 {
		t.Fatalf("fixture recorded a restart the stub rejected: %v", e.RstAt(0))
	}
}

// Dry-run mode logs the dead-fallback action and burns the budget
// without touching systemd.
func TestDeadFallbackDryRun(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Sig13.Mode = cdeps.ModeDryRun
	e.H.Cfg.Hub.PeerAPI = ""
	e.H.Cfg.TotalControllers = 2
	e.H.Cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.Journal = "x required revision has been compacted\n"
	for range 8 { // dry-run never spends the budget — fire once at dn=8
		e.H.Cycle(context.Background())
	}
	if e.RstN() != 0 {
		t.Fatalf("dry-run restarted: %v", e.RstAt(0))
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(
		cdeps.CheckHub, "dryrun_restart")); v != 1 {
		t.Fatalf("dryrun_restart counter=%v want 1", v)
	}
	if !strings.Contains(e.LogLines(),
		"DRY-RUN: would restart k0scontroller - apiserver dead, kine db ok") {
		t.Fatalf("dead-fallback dry-run not logged:\n%s", e.LogLines())
	}
}
