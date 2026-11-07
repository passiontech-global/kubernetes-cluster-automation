// kine_ttl_test.go — the kine TTL dead/rewedge-loop kill guard and
// the suspect-log dedupe tests (split out of the old
// apiserverhub_test.go — the TTL check lives in the kine domain
// package).
package kine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// --- Guard a tail: kine TTL ---

func TestTTLDeadKill(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 3001, "kine", []string{"kine"}, 1000) // age > 300s
	e.Journal = "E TTL initial list failed: context deadline\n"
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("kine-ttl-dead missing")
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 3001 {
		t.Fatalf("expected kine kill, got %v", e.Kills)
	}
}

func TestTTLYoungPidSpared(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 3001, "kine", []string{"kine"}, 60) // inside seed window
	e.Journal = "E TTL initial list failed\n"
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatal("killed a kine still in its seed window")
	}
}

func TestTTLRewedgeLoopSuppressesFastKill(t *testing.T) {
	e := fixture(t)
	e.Journal = "E TTL event watch failed\n"
	e.MkProc(t, 3001, "kine", []string{"kine"}, 1000)
	e.H.Cycle(context.Background()) // pid 3001 wedged → kill (rew=1)
	if len(e.Kills) != 1 {
		t.Fatal("first wedged pid not killed")
	}
	// Respawn re-wedges from boot → rew=2 >= RewedgeCycles → loop.
	// Remove the old pid dir so pgrep sees the new pid.
	if err := os.RemoveAll(filepath.Join(e.Proc, "3001")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3002, "kine", []string{"kine"}, 400)
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop missing after rewedge")
	}
	// Loop path kills at CTL cadence — a second pid IS killed once
	// (the recovery probe), but the budget is spent now.
	e.H.Cycle(context.Background())
	killsAfter := len(e.Kills)
	if killsAfter > 2 {
		t.Fatalf("loop path over-killed: %d", len(e.Kills))
	}
	// Clean pid resets.
	e.Journal = ""
	if err := os.RemoveAll(filepath.Join(e.Proc, "3002")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3003, "kine", []string{"kine"}, 1000)
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateKineTTLDead) || e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("clean kine did not clear TTL latches")
	}
}

// --- suspect-log dedupe (held-latch per-cycle spam, nonprod 2026-10) ---

func TestTTLLoopSuspectLogDeduped(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.Journal = "E TTL event watch failed\n"
	const line = "suspect: kine-ttl-loop"

	// Two consecutive wedged pids → loop latch; the suspect line
	// lands once on the latch-enter cycle.
	e.MkProc(t, 3001, "kine", []string{"kine"}, 1000)
	e.H.Cycle(ctx) // rew=1: tier-1 kill
	if len(e.Kills) != 1 {
		t.Fatalf("first wedged pid not killed: %v", e.Kills)
	}
	if err := os.RemoveAll(filepath.Join(e.Proc, "3001")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3002, "kine", []string{"kine"}, 400)
	e.H.Cycle(ctx) // rew=2 → kine-ttl-loop latched
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not latched")
	}
	if n := e.CountLogLines(line); n != 1 {
		t.Fatalf("suspect lines=%d want 1 on latch entry", n)
	}

	// Held latch: repeated wedged cycles emit no repeat within the
	// cadence — but the rewedge counter still tracks new pids.
	for i := 0; i < 3; i++ {
		e.H.Cycle(ctx)
	}
	if err := os.RemoveAll(filepath.Join(e.Proc, "3002")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3003, "kine", []string{"kine"}, 400)
	e.H.Cycle(ctx) // rew=3, same latch episode
	if rew := e.H.State.Counter(cdeps.FileCtrTTLRewedge); rew != 3 {
		t.Fatalf("rewedge counter=%d want 3 — increments must continue under dedupe", rew)
	}
	if n := e.CountLogLines(line); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}

	// Cadence expiry → exactly one re-reminder, then deduped again.
	e.Now = e.Now.Add(e.H.Cfg.SuspectLogCadence + time.Second)
	e.H.Cycle(ctx)
	if n := e.CountLogLines(line); n != 2 {
		t.Fatalf("re-reminder missing after cadence expiry: %d", n)
	}
	e.H.Cycle(ctx)
	if n := e.CountLogLines(line); n != 2 {
		t.Fatalf("suspect repeated inside cadence window: %d", n)
	}

	// Latch exit (clean journal) drops the dedupe budget, so a
	// re-entry logs a fresh line even inside the cadence window.
	e.Journal = ""
	e.H.Cycle(ctx)
	if e.HasState(cdeps.StateKineTTLLoop) || e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("clean kine did not clear the TTL latches")
	}
	e.Journal = "E TTL event watch failed\n"
	e.H.Cycle(ctx) // pid 3003 wedges again: rew=1 — no loop yet
	if n := e.CountLogLines(line); n != 2 {
		t.Fatalf("unexpected suspect before loop re-entry: %d", n)
	}
	if err := os.RemoveAll(filepath.Join(e.Proc, "3003")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3004, "kine", []string{"kine"}, 400)
	e.H.Cycle(ctx) // rew=2 → latch re-entered
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not re-latched")
	}
	if n := e.CountLogLines(line); n != 3 {
		t.Fatalf("no fresh suspect on latch re-entry: %d", n)
	}
}

func TestCacheStaleSuspectLogDeduped(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	// Healthy rv (gap measurable, no wedge) isolates the stale
	// check — the dead-fallback path is not exercised.
	e.SetRV("127.0.0.1:6443", false, 70000, true)
	e.SetRV("127.0.0.1:6443", true, 70000, true)
	const line = "suspect: apiserver-cache-stale -"

	e.Journal = strings.Repeat(
		"x required revision has been compacted\n", 20)
	for i := 0; i < 3; i++ { // latch held across cycles → one line
		e.H.Cycle(ctx)
	}
	if !e.HasState(cdeps.StateCacheStale) {
		t.Fatal("apiserver-cache-stale not latched")
	}
	if n := e.CountLogLines(line); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}
	// Cadence expiry → exactly one re-reminder.
	e.Now = e.Now.Add(e.H.Cfg.SuspectLogCadence + time.Second)
	e.H.Cycle(ctx)
	if n := e.CountLogLines(line); n != 2 {
		t.Fatalf("re-reminder missing after cadence expiry: %d", n)
	}
	// Journal quiets → latch exits; a re-entry must log fresh.
	e.Journal = ""
	e.H.Cycle(ctx)
	if e.HasState(cdeps.StateCacheStale) {
		t.Fatal("stale latch not cleared")
	}
	e.Journal = strings.Repeat(
		"x required revision has been compacted\n", 20)
	e.H.Cycle(ctx)
	if n := e.CountLogLines(line); n != 3 {
		t.Fatalf("no fresh suspect on latch re-entry: %d", n)
	}
}
