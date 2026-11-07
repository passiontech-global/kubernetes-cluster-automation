// apiserverhub_test.go — apiserver-hub wedge/dead-fallback guards, the kine TTL tail, and suspect-log dedupe.

package controllerhygiene

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Guard a: wedge detection ---

func TestGapWedgePeerFreshRestarts(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	// rv_now - rv_cache > 10000; peer close to head => fresh.
	e.setRV(self, false, 20000, true)
	e.setRV(self, true, 5000, true)
	e.setRV(peer, true, 19900, true)
	e.h.Cycle(context.Background()) // gn=1
	e.h.Cycle(context.Background()) // gn=2 => wedge confirmed
	if !e.hasState(stateCacheWedged) {
		t.Fatal("state-apiserver-cache-wedged missing")
	}
	if e.rstN() != 1 || e.rstAt(0) != "k0scontroller.service" {
		t.Fatalf("expected 1 restart, got %d", e.rstN())
	}
	// Rate budget spent.
	if h := e.h.state.Epoch(filepath.Join(e.state, fileRateRestart)); h == 0 {
		t.Fatal("last-sig13-restart budget not spent")
	}
}

func TestGapWedgePeerStaleHeld(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.setRV(self, false, 90000, true)
	e.setRV(self, true, 5000, true)
	e.setRV(peer, true, 4000, true) // peer cache far behind too
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("restart happened while peer stale and solo cycles short")
	}
	if !e.hasState(stateCacheWedged) {
		t.Fatal("wedge state missing")
	}
}

func TestFrozenWedgeSoloAfterCycles(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	e.h.cfg.Hub.PeerAPI = "" // single-hub => always first
	// W13 Gap#2: pin a 2-controller topology so the solo-restart
	// mechanics under test are not masked by the SPOF doubled
	// streak (TestSPOFStreakCycles owns that contract).
	e.h.cfg.TotalControllers = 2
	rvN := int64(100)
	// rv_cache frozen at 50 while rv_now grows — the first cycle
	// only seeds last-rvc, so FrozenCycles=2 trips on cycle 3.
	for i := 0; i < 3; i++ {
		e.setRV(self, true, 50, true)
		e.setRV(self, false, rvN, true)
		rvN += 10
		e.h.Cycle(context.Background())
	}
	if !e.hasState(stateCacheWedged) {
		t.Fatal("frozen wedge not detected after FrozenCycles")
	}
	// Solo path needs SoloCycles gap-counter (each wedged cycle
	// increments) — keep cycling until restart.
	for i := 0; i < 10 && e.rstN() == 0; i++ {
		e.setRV(self, false, rvN, true)
		rvN += 10
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 1 {
		t.Fatalf("expected solo restart, got %d", e.rstN())
	}
}

func TestIdleClusterNoFrozen(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	// rv_now == rv_cache — standing still is not wedge evidence.
	for i := 0; i < 4; i++ {
		e.setRV(self, true, 70, true)
		e.setRV(self, false, 70, true)
		e.h.Cycle(context.Background())
	}
	if e.hasState(stateCacheWedged) {
		t.Fatal("idle cluster latched as wedged")
	}
	if e.rstN() != 0 {
		t.Fatal("idle cluster triggered restart")
	}
}

func TestRecoveryClearsWedge(t *testing.T) {
	e := fixture(t)
	self := "127.0.0.1:6443"
	peer := "10.0.0.2:6443"
	e.setRV(self, false, 90000, true)
	e.setRV(self, true, 1000, true)
	e.setRV(peer, true, 89900, true)
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if !e.hasState(stateCacheWedged) {
		t.Fatal("precondition: wedge not latched")
	}
	// Cache catches up.
	e.setRV(self, true, 89500, true)
	e.h.Cycle(context.Background())
	if e.hasState(stateCacheWedged) {
		t.Fatal("wedge state not cleared on recovery")
	}
}

func TestDeadFallbackKineOK(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Hub.PeerAPI = "" // single hub
	// W13 Gap#2: pin a 2-controller topology — the dead-fallback
	// streak would otherwise double before the restart.
	e.h.cfg.TotalControllers = 2
	e.h.cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.journal = "x required revision has been compacted\n" // cache_errs > 0
	// Both queries dead, DB healthy → dead-fallback after SoloCycles.
	for i := 0; i < 9 && e.rstN() == 0; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 1 {
		t.Fatalf("dead-fallback restart missing: %d", e.rstN())
	}
	if e.hasState(stateKineUnreachable) {
		t.Fatal("kine-backend-unreachable latched despite healthy DB")
	}
}

func TestDeadFallbackKineDead(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Hub.KineDBProbe = "10.0.0.9:6432"
	e.journal = "x required revision has been compacted\n"
	e.pgOK = false // DB broken → apiserver restart is useless
	for i := 0; i < 12; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("restart ran while DB dead")
	}
	if !e.hasState(stateKineUnreachable) {
		t.Fatal("kine-backend-unreachable missing")
	}
}

func TestSecondHubNeverSolo(t *testing.T) {
	e := fixture(t)
	// Self sorts AFTER peer → second hub.
	e.h.cfg.Hub.SelfAPI = "10.0.0.9:6443"
	e.h.cfg.Hub.PeerAPI = "10.0.0.2:6443"
	self := "127.0.0.1:6443"
	e.setRV(self, false, 90000, true)
	e.setRV(self, true, 5000, true)
	// peer unreachable → peer_note=unreachable, not fresh.
	for i := 0; i < 12; i++ {
		e.h.Cycle(context.Background())
	}
	if e.rstN() != 0 {
		t.Fatal("second hub restarted without fresh peer")
	}
}

// --- Guard a tail: kine TTL ---

func TestTTLDeadKill(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 3001, "kine", []string{"kine"}, 1000) // age > 300s
	e.journal = "E TTL initial list failed: context deadline\n"
	e.h.Cycle(context.Background())
	if !e.hasState(stateKineTTLDead) {
		t.Fatal("kine-ttl-dead missing")
	}
	if len(e.kills) != 1 || e.kills[0].pid != 3001 {
		t.Fatalf("expected kine kill, got %v", e.kills)
	}
}

func TestTTLYoungPidSpared(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 3001, "kine", []string{"kine"}, 60) // inside seed window
	e.journal = "E TTL initial list failed\n"
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("killed a kine still in its seed window")
	}
}

func TestTTLRewedgeLoopSuppressesFastKill(t *testing.T) {
	e := fixture(t)
	e.journal = "E TTL event watch failed\n"
	e.mkProc(t, 3001, "kine", []string{"kine"}, 1000)
	e.h.Cycle(context.Background()) // pid 3001 wedged → kill (rew=1)
	if len(e.kills) != 1 {
		t.Fatal("first wedged pid not killed")
	}
	// Respawn re-wedges from boot → rew=2 >= RewedgeCycles → loop.
	// Remove the old pid dir so pgrep sees the new pid.
	if err := os.RemoveAll(filepath.Join(e.proc, "3001")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3002, "kine", []string{"kine"}, 400)
	e.h.Cycle(context.Background())
	if !e.hasState(stateKineTTLLoop) {
		t.Fatal("kine-ttl-loop missing after rewedge")
	}
	// Loop path kills at CTL cadence — a second pid IS killed once
	// (the recovery probe), but the budget is spent now.
	e.h.Cycle(context.Background())
	killsAfter := len(e.kills)
	if killsAfter > 2 {
		t.Fatalf("loop path over-killed: %d", len(e.kills))
	}
	// Clean pid resets.
	e.journal = ""
	if err := os.RemoveAll(filepath.Join(e.proc, "3002")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3003, "kine", []string{"kine"}, 1000)
	e.h.Cycle(context.Background())
	if e.hasState(stateKineTTLDead) || e.hasState(stateKineTTLLoop) {
		t.Fatal("clean kine did not clear TTL latches")
	}
}

// --- suspect-log dedupe (held-latch per-cycle spam, nonprod 2026-10) ---

func TestTTLLoopSuspectLogDeduped(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.journal = "E TTL event watch failed\n"
	const line = "suspect: kine-ttl-loop"

	// Two consecutive wedged pids → loop latch; the suspect line
	// lands once on the latch-enter cycle.
	e.mkProc(t, 3001, "kine", []string{"kine"}, 1000)
	e.h.Cycle(ctx) // rew=1: tier-1 kill
	if len(e.kills) != 1 {
		t.Fatalf("first wedged pid not killed: %v", e.kills)
	}
	if err := os.RemoveAll(filepath.Join(e.proc, "3001")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3002, "kine", []string{"kine"}, 400)
	e.h.Cycle(ctx) // rew=2 → kine-ttl-loop latched
	if !e.hasState(stateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not latched")
	}
	if n := countLogLines(t, e, line); n != 1 {
		t.Fatalf("suspect lines=%d want 1 on latch entry", n)
	}

	// Held latch: repeated wedged cycles emit no repeat within the
	// cadence — but the rewedge counter still tracks new pids.
	for i := 0; i < 3; i++ {
		e.h.Cycle(ctx)
	}
	if err := os.RemoveAll(filepath.Join(e.proc, "3002")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3003, "kine", []string{"kine"}, 400)
	e.h.Cycle(ctx) // rew=3, same latch episode
	if rew := e.h.state.Counter(fileCtrTTLRewedge); rew != 3 {
		t.Fatalf("rewedge counter=%d want 3 — increments must continue under dedupe", rew)
	}
	if n := countLogLines(t, e, line); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}

	// Cadence expiry → exactly one re-reminder, then deduped again.
	e.now = e.now.Add(e.h.cfg.SuspectLogCadence + time.Second)
	e.h.Cycle(ctx)
	if n := countLogLines(t, e, line); n != 2 {
		t.Fatalf("re-reminder missing after cadence expiry: %d", n)
	}
	e.h.Cycle(ctx)
	if n := countLogLines(t, e, line); n != 2 {
		t.Fatalf("suspect repeated inside cadence window: %d", n)
	}

	// Latch exit (clean journal) drops the dedupe budget, so a
	// re-entry logs a fresh line even inside the cadence window.
	e.journal = ""
	e.h.Cycle(ctx)
	if e.hasState(stateKineTTLLoop) || e.hasState(stateKineTTLDead) {
		t.Fatal("clean kine did not clear the TTL latches")
	}
	e.journal = "E TTL event watch failed\n"
	e.h.Cycle(ctx) // pid 3003 wedges again: rew=1 — no loop yet
	if n := countLogLines(t, e, line); n != 2 {
		t.Fatalf("unexpected suspect before loop re-entry: %d", n)
	}
	if err := os.RemoveAll(filepath.Join(e.proc, "3003")); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 3004, "kine", []string{"kine"}, 400)
	e.h.Cycle(ctx) // rew=2 → latch re-entered
	if !e.hasState(stateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not re-latched")
	}
	if n := countLogLines(t, e, line); n != 3 {
		t.Fatalf("no fresh suspect on latch re-entry: %d", n)
	}
}

func TestCacheStaleSuspectLogDeduped(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	// Healthy rv (gap measurable, no wedge) isolates the stale
	// check — the dead-fallback path is not exercised.
	e.setRV("127.0.0.1:6443", false, 70000, true)
	e.setRV("127.0.0.1:6443", true, 70000, true)
	const line = "suspect: apiserver-cache-stale -"

	e.journal = strings.Repeat(
		"x required revision has been compacted\n", 20)
	for i := 0; i < 3; i++ { // latch held across cycles → one line
		e.h.Cycle(ctx)
	}
	if !e.hasState(stateCacheStale) {
		t.Fatal("apiserver-cache-stale not latched")
	}
	if n := countLogLines(t, e, line); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}
	// Cadence expiry → exactly one re-reminder.
	e.now = e.now.Add(e.h.cfg.SuspectLogCadence + time.Second)
	e.h.Cycle(ctx)
	if n := countLogLines(t, e, line); n != 2 {
		t.Fatalf("re-reminder missing after cadence expiry: %d", n)
	}
	// Journal quiets → latch exits; a re-entry must log fresh.
	e.journal = ""
	e.h.Cycle(ctx)
	if e.hasState(stateCacheStale) {
		t.Fatal("stale latch not cleared")
	}
	e.journal = strings.Repeat(
		"x required revision has been compacted\n", 20)
	e.h.Cycle(ctx)
	if n := countLogLines(t, e, line); n != 3 {
		t.Fatalf("no fresh suspect on latch re-entry: %d", n)
	}
}
