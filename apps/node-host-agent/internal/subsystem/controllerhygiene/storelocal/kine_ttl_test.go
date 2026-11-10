// kine_ttl_test.go — the kine TTL dead/rewedge-loop kill guard and
// the suspect-log dedupe tests (split out of the old
// apiserverhub_test.go — the TTL check lives in the kine domain
// package).
package storelocal_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// A proc whose /proc/<pid>/stat is unreadable degenerates the TTL
// journal window to "now" — the guard must say so and stay passive.
func TestTTLAgeUnreadableWarns(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	// comm-only proc dir with a malformed stat (no closing paren) —
	// FindByComm finds it, PIDAgeSeconds errors on it.
	pidDir := filepath.Join(e.Proc, "3009")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("kine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte("3009 (kine broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.Journal = "E TTL initial list failed\n"
	e.H.Cycle(ctx)
	if n := e.CountLogLines("age unreadable"); n != 1 {
		t.Fatalf("age-unreadable warn lines=%d want 1", n)
	}
	if !e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("kine-ttl-dead missing on wedged journal")
	}
	if len(e.Kills) != 0 {
		t.Fatalf("killed kine with unreadable age: %v", e.Kills)
	}
}

// --- loop path (rewedge >= RewedgeCycles): recovery-probe kill ---

func TestTTLLoopRecoveryProbeKill(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.H.Cfg.KineTTL.RewedgeCycles = 1 // one wedged pid → loop immediately
	e.Journal = "E TTL event watch failed\n"
	e.MkProc(t, 3011, "kine", []string{"kine"}, 1000)
	e.H.Cycle(ctx)
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not latched on first wedged pid")
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 3011 {
		t.Fatalf("expected recovery-probe kill of 3011, got %v", e.Kills)
	}
	if n := e.CountLogLines("recovery probe kine-ttl-loop"); n != 1 {
		t.Fatalf("recovery-probe ACTION lines=%d want 1", n)
	}
	// The loop kill budget is spent — the next wedged cycle stays
	// silent (low cadence), no second kill.
	e.H.Cycle(ctx)
	if len(e.Kills) != 1 {
		t.Fatalf("loop path over-killed: %v", e.Kills)
	}
}

func TestTTLLoopRecoveryKillFailure(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.H.Cfg.KineTTL.RewedgeCycles = 1
	e.Journal = "E TTL event watch failed\n"
	e.MkProc(t, 3012, "kine", []string{"kine"}, 1000)
	oldKill := e.H.Cfg.KillFn
	e.H.Cfg.KillFn = func(int, syscall.Signal) error { return errors.New("EPERM") }
	t.Cleanup(func() { e.H.Cfg.KillFn = oldKill })
	e.H.Cycle(ctx)
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not latched")
	}
	if n := e.CountLogLines("suspect: kill kine pid="); n != 1 {
		t.Fatalf("kill-failure warn lines=%d want 1", n)
	}
}

func TestTTLLoopRecoveryDryRun(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.H.Cfg.KineTTL.RewedgeCycles = 1
	e.H.Cfg.KineTTL.Mode = cdeps.ModeDryRun
	e.Journal = "E TTL event watch failed\n"
	e.MkProc(t, 3013, "kine", []string{"kine"}, 1000)
	e.H.Cycle(ctx)
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not latched in dry-run")
	}
	if n := e.CountLogLines("DRY-RUN: would kill kine pid="); n != 1 {
		t.Fatalf("dry-run lines=%d want 1", n)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("dry-run killed kine: %v", e.Kills)
	}
}

// --- tier-1 (chance wedge) branches ---

func TestTTLRestartCooldownSkip(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.Journal = "E TTL initial list failed\n"
	e.MkProc(t, 3015, "kine", []string{"kine"}, 1000)
	e.H.Cycle(ctx) // tier-1 kill spends the MinRestart budget
	if len(e.Kills) != 1 {
		t.Fatalf("first wedge not killed: %v", e.Kills)
	}
	// Same pid still wedged, budget spent → suspect + skip, no kill.
	e.H.Cycle(ctx)
	if len(e.Kills) != 1 {
		t.Fatalf("restart cooldown did not suppress the kill: %v", e.Kills)
	}
	if n := e.CountLogLines("in restart cooldown"); n != 1 {
		t.Fatalf("cooldown suspect lines=%d want 1", n)
	}
}

func TestTTLKillFailureWarns(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.Journal = "E TTL initial list failed\n"
	e.MkProc(t, 3017, "kine", []string{"kine"}, 1000)
	oldKill := e.H.Cfg.KillFn
	e.H.Cfg.KillFn = func(int, syscall.Signal) error { return errors.New("EPERM") }
	t.Cleanup(func() { e.H.Cfg.KillFn = oldKill })
	e.H.Cycle(ctx)
	if n := e.CountLogLines("suspect: kill kine pid="); n != 1 {
		t.Fatalf("kill-failure warn lines=%d want 1", n)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("failed kill recorded: %v", e.Kills)
	}
}

func TestTTLDryRunSparesKine(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.H.Cfg.KineTTL.Mode = cdeps.ModeDryRun
	e.Journal = "E TTL initial list failed\n"
	e.MkProc(t, 3018, "kine", []string{"kine"}, 1000)
	e.H.Cycle(ctx)
	if !e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("kine-ttl-dead not latched in dry-run")
	}
	if n := e.CountLogLines("DRY-RUN: would kill kine pid="); n != 1 {
		t.Fatalf("dry-run lines=%d want 1", n)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("dry-run killed kine: %v", e.Kills)
	}
}
