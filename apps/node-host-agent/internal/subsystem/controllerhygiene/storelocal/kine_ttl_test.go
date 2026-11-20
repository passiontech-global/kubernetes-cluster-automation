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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/storelocal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// --- Guard a tail: kine TTL ---

// The never-started signature (nonprod 2026-11-17/18): no kine pid in
// either cgroup while the unit is active — the old branch counted the
// cycle "ok" and the outage ran 25h without a signal.
func TestKineDownLatchedWhenPidAbsent(t *testing.T) {
	e := fixture(t)
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineDown) {
		t.Fatal("kine-down missing with no kine pid anywhere")
	}
}

// Phase-3 split hosts run kine as the standalone kine.service unit —
// an empty k0scontroller cgroup is the expected shape there, not an
// outage.
func TestExternalKineServiceSparesKineDown(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 3100, "kine", []string{"kine"}, 1000)
	testutil.WriteFile(t, filepath.Join(e.Proc, "3100", "cgroup"),
		"0::/system.slice/kine.service\n")
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateKineDown) {
		t.Fatal("kine-down latched although kine.service owns the pid")
	}
}

func TestKineDownClearedWhenPidReturns(t *testing.T) {
	e := fixture(t)
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineDown) {
		t.Fatal("precondition: kine-down not latched")
	}
	e.MkProc(t, 3200, "kine", []string{"kine"}, 1000)
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateKineDown) {
		t.Fatal("kine-down not cleared when the pid returned")
	}
}

// Bind conflict with a foreign port holder: the respawn dies before
// any TTL line exists — the bind line is the only journal evidence.
func TestTTLBindConflictKills(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 3300, "kine", []string{"kine"}, 1000)
	e.Journal = "FATA error creating the metrics listener: " +
		"listen tcp :2380: bind: address already in use\n"
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("bind-conflict wedge not latched as kine-ttl-dead")
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 3300 {
		t.Fatalf("expected kine kill, got %v", e.Kills)
	}
}

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

	// Latch exit needs a pid the journal never flagged: the recorded
	// wedged pid can never un-wedge (its single boot-time line ages
	// out of the bounded lookback while cooldowns hold remediation),
	// so a clean journal on the SAME pid must NOT clear the latch —
	// only a fresh pid + clean journal is the real "loop broken"
	// signal. Swap in pid 3004 with an empty journal for the exit.
	e.Journal = ""
	if err := os.RemoveAll(filepath.Join(e.Proc, "3003")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3004, "kine", []string{"kine"}, 400)
	e.H.Cycle(ctx)
	if e.HasState(cdeps.StateKineTTLLoop) || e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("clean kine did not clear the TTL latches")
	}
	e.Journal = "E TTL event watch failed\n"
	e.H.Cycle(ctx) // pid 3004 wedges again: rew=1 — no loop yet
	if n := e.CountLogLines(line); n != 2 {
		t.Fatalf("unexpected suspect before loop re-entry: %d", n)
	}
	if err := os.RemoveAll(filepath.Join(e.Proc, "3004")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3005, "kine", []string{"kine"}, 400)
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
	// The comm→pid lookup is cgroup-scoped — this proc must sit
	// under k0scontroller.service to be found at all.
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"),
		[]byte("0::/system.slice/k0scontroller.service\n"), 0o644); err != nil {
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

func TestEmbeddedEtcdProcessSparesAndClearsKineDown(t *testing.T) {
	e := fixture(t)
	// First latch StateKineDown when neither kine nor etcd is present.
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineDown) {
		t.Fatal("precondition: kine-down not latched")
	}
	// Live etcd process under k0scontroller.service clears StateKineDown.
	e.MkProc(t, 3400, "etcd", []string{"etcd"}, 1000)
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateKineDown) {
		t.Fatal("kine-down latched/retained on embedded etcd host")
	}
}

func TestEmbeddedEtcdDiskMarkersSpareKineDown(t *testing.T) {
	t.Run("etcd_dir", func(t *testing.T) {
		e := fixture(t)
		k0sDir := filepath.Join(filepath.Dir(e.State), "k0s-etcd")
		if err := os.MkdirAll(filepath.Join(k0sDir, "etcd"), 0o755); err != nil {
			t.Fatal(err)
		}
		e.H.Cfg.K0sDir = k0sDir
		e.H.Cycle(context.Background())
		if e.HasState(cdeps.StateKineDown) {
			t.Fatal("kine-down latched with <K0sDir>/etcd directory present")
		}
	})
	t.Run("etcdctl_and_ca", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.K0sDir = e.MkEtcdHost(t)
		e.H.Cycle(context.Background())
		if e.HasState(cdeps.StateKineDown) {
			t.Fatal("kine-down latched with bin/etcdctl + pki/etcd/ca.crt present")
		}
	})
}

func TestExplicitKineMarkersStillLatchKineDown(t *testing.T) {
	t.Run("kine_db_probe", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.K0sDir = e.MkEtcdHost(t)
		e.H.Cfg.Hub.KineDBProbe = "10.0.0.9:6432"
		e.H.Cycle(context.Background())
		if !e.HasState(cdeps.StateKineDown) {
			t.Fatal("kine-down suppressed despite explicit KineDBProbe")
		}
	})
	t.Run("state_db", func(t *testing.T) {
		e := fixture(t)
		k0sDir := e.MkEtcdHost(t)
		testutil.WriteFile(t, filepath.Join(k0sDir, "db", "state.db"), "sqlite")
		e.H.Cfg.K0sDir = k0sDir
		e.H.Cycle(context.Background())
		if !e.HasState(cdeps.StateKineDown) {
			t.Fatal("kine-down suppressed despite <K0sDir>/db/state.db present")
		}
	})
	t.Run("kine_service_unit", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.K0sDir = e.MkEtcdHost(t)
		unitDir := filepath.Dir(e.H.Cfg.K0sControllerUnitFile)
		testutil.WriteFile(t, filepath.Join(unitDir, "kine.service"), "[Service]\n")
		e.H.Cycle(context.Background())
		if !e.HasState(cdeps.StateKineDown) {
			t.Fatal("kine-down suppressed despite kine.service unit file present")
		}
	})
}

func TestKineTTLDeadHoldEmergencyHeal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		annos  map[string]string
		taints []string
	}{
		{
			name:  "cluster_maintenance_anno",
			annos: map[string]string{nodecond.AnnoClusterMaintenanceUntil: "2099-01-01T00:00:00Z"},
		},
		{
			name:   "kured_reboot_taint",
			taints: []string{nodecond.KuredRebootTaintKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			var active atomic.Bool
			active.Store(true)
			e.H.Cfg.Coord = &nodecoord.Coord{
				Now: func() time.Time { return e.Now },
				GetNode: func(context.Context) (map[string]string, []string, error) {
					if active.Load() {
						return tc.annos, tc.taints, nil
					}
					return nil, nil, nil
				},
			}
			e.MkProc(t, 3020, "kine", []string{"kine"}, 1000)
			e.Journal = "E TTL initial list failed\n"

			e.H.Cycle(context.Background())
			if !e.HasState(cdeps.StateKineTTLDead) {
				t.Fatal("kine-ttl-dead not latched under maintenance hold")
			}
			if len(e.Kills) != 0 {
				t.Fatalf("killed kine while maintenance held: %v", e.Kills)
			}
			if got := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateTTLKill)); got != 0 {
				t.Fatalf("FileRateTTLKill spent while held: %d", got)
			}
			if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(cdeps.CheckKineTTL, "maint_hold")); v != 1 {
				t.Fatalf("maint_hold actions=%v want 1", v)
			}

			// Maintenance clears -> advance past nodecoord.CacheTTL so Coord refreshes.
			active.Store(false)
			e.Now = e.Now.Add(nodecoord.CacheTTL + time.Second)
			e.H.Cycle(context.Background())
			if len(e.Kills) != 1 || e.Kills[0].PID != 3020 {
				t.Fatalf("expected kill after maintenance cleared, got %v", e.Kills)
			}
		})
	}
}

func TestKineTTLLoopHoldEmergencyHeal(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.KineTTL.RewedgeCycles = 1
	var active atomic.Bool
	active.Store(true)
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetNode: func(context.Context) (map[string]string, []string, error) {
			if active.Load() {
				return map[string]string{nodecond.AnnoClusterMaintenanceUntil: "2099-01-01T00:00:00Z"}, nil, nil
			}
			return nil, nil, nil
		},
	}
	e.MkProc(t, 3021, "kine", []string{"kine"}, 1000)
	e.Journal = "E TTL event watch failed\n"

	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKineTTLLoop) {
		t.Fatal("kine-ttl-loop not latched under maintenance hold")
	}
	if len(e.Kills) != 0 {
		t.Fatalf("loop path killed kine while maintenance held: %v", e.Kills)
	}
	if e.CountLogLines("suspect: kine-ttl-loop — cluster maintenance in progress") != 1 {
		t.Fatalf("expected distinct kine-ttl-loop hold suspect log:\n%s", e.LogLines())
	}
	if got := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateTTLKill)); got != 0 {
		t.Fatalf("FileRateTTLKill spent while held: %d", got)
	}
	if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(cdeps.CheckKineTTL, "maint_hold")); v != 1 {
		t.Fatalf("maint_hold actions=%v want 1", v)
	}

	active.Store(false)
	e.Now = e.Now.Add(nodecoord.CacheTTL + time.Second)
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 3021 {
		t.Fatalf("expected loop recovery kill after maintenance cleared, got %v", e.Kills)
	}
}

func TestKineTTLFailOpenOnCoordError(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetNode: func(context.Context) (map[string]string, []string, error) {
			return nil, nil, errors.New("apiserver unreachable")
		},
	}
	e.MkProc(t, 3022, "kine", []string{"kine"}, 1000)
	e.Journal = "E TTL initial list failed\n"

	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 3022 {
		t.Fatalf("HoldEmergencyHeal failed closed on transient Coord error: kills=%v", e.Kills)
	}
}

func TestKineTTLCtxErrAbortsCachedWedgedDead(t *testing.T) {
	e := fixture(t)
	var coordCalls atomic.Int32
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetNode: func(context.Context) (map[string]string, []string, error) {
			coordCalls.Add(1)
			return map[string]string{nodecond.AnnoClusterMaintenanceUntil: "2099-01-01T00:00:00Z"}, nil, nil
		},
	}
	// Cycle 1: young pid records FileTTLWedgedPID + StateKineTTLDead without killing.
	e.MkProc(t, 3050, "kine", []string{"kine"}, 60)
	e.Journal = "E TTL initial list failed\n"
	ttl := cdepstest.Check[*storelocal.TTLCheck](e.H, cdeps.CheckKineTTL)
	ttl.Run(context.Background())
	if !e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("precondition: kine-ttl-dead not latched")
	}
	if got := e.H.ReadState(cdeps.FileTTLWedgedPID); got != "3050" {
		t.Fatalf("precondition: FileTTLWedgedPID=%q want 3050", got)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("precondition: young pid killed: %v", e.Kills)
	}

	// Cycle 2: pid survived past MinProcAge with cached ttlDead + cancelled ctx.
	if err := os.RemoveAll(filepath.Join(e.Proc, "3050")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3050, "kine", []string{"kine"}, 400)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ttl.Run(ctx)

	if got := coordCalls.Load(); got != 0 {
		t.Fatalf("cancelled ctx called Coord %d times, want 0", got)
	}
	if got := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateTTLKill)); got != 0 {
		t.Fatalf("cancelled ctx spent FileRateTTLKill: %d", got)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("cancelled ctx killed kine: %v", e.Kills)
	}
	if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKineTTL, "aborted")); v != 1 {
		t.Fatalf("cycles{kine-ttl,aborted}=%v want 1", v)
	}
}

func TestKineTTLCtxErrAbortsLoopAfterCooldown(t *testing.T) {
	t.Run("after_cooldown", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.KineTTL.RewedgeCycles = 1
		var coordCalls atomic.Int32
		e.H.Cfg.Coord = &nodecoord.Coord{
			Now: func() time.Time { return e.Now },
			GetNode: func(context.Context) (map[string]string, []string, error) {
				coordCalls.Add(1)
				return nil, nil, nil
			},
		}
		e.H.State.RateSpend(cdeps.FileRateTTLKill)
		spentBefore := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateTTLKill))
		e.MkProc(t, 3052, "kine", []string{"kine"}, 400)
		e.Journal = "E TTL event watch failed\n"

		ttl := cdepstest.Check[*storelocal.TTLCheck](e.H, cdeps.CheckKineTTL)
		ttl.Run(context.Background())
		if !e.HasState(cdeps.StateKineTTLLoop) {
			t.Fatal("precondition: kine-ttl-loop not latched")
		}
		if len(e.Kills) != 0 {
			t.Fatalf("precondition: cooldown did not spare kine: %v", e.Kills)
		}

		e.Now = e.Now.Add(e.H.Cfg.KineTTL.CtlRestart + time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ttl.Run(ctx)

		if got := coordCalls.Load(); got != 0 {
			t.Fatalf("cancelled ctx called Coord %d times, want 0", got)
		}
		if got := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateTTLKill)); got != spentBefore {
			t.Fatalf("cancelled ctx changed FileRateTTLKill: got %d want %d", got, spentBefore)
		}
		if len(e.Kills) != 0 {
			t.Fatalf("cancelled ctx killed kine: %v", e.Kills)
		}
		if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKineTTL, "aborted")); v != 1 {
			t.Fatalf("cycles{kine-ttl,aborted}=%v want 1", v)
		}
	})

	t.Run("unspent_budget", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.KineTTL.RewedgeCycles = 1
		e.H.Cfg.KineTTL.Mode = cdeps.ModeDryRun
		var coordCalls atomic.Int32
		e.H.Cfg.Coord = &nodecoord.Coord{
			Now: func() time.Time { return e.Now },
			GetNode: func(context.Context) (map[string]string, []string, error) {
				coordCalls.Add(1)
				return nil, nil, nil
			},
		}
		e.MkProc(t, 3053, "kine", []string{"kine"}, 400)
		e.Journal = "E TTL event watch failed\n"

		ttl := cdepstest.Check[*storelocal.TTLCheck](e.H, cdeps.CheckKineTTL)
		ttl.Run(context.Background())
		if !e.HasState(cdeps.StateKineTTLLoop) {
			t.Fatal("precondition: kine-ttl-loop not latched")
		}

		e.H.Cfg.KineTTL.Mode = cdeps.ModeEnforce
		coordCalls.Store(0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ttl.Run(ctx)

		if got := coordCalls.Load(); got != 0 {
			t.Fatalf("cancelled ctx called Coord %d times, want 0", got)
		}
		if got := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateTTLKill)); got != 0 {
			t.Fatalf("cancelled ctx spent FileRateTTLKill: %d", got)
		}
		if len(e.Kills) != 0 {
			t.Fatalf("cancelled ctx killed kine: %v", e.Kills)
		}
		if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKineTTL, "aborted")); v != 1 {
			t.Fatalf("cycles{kine-ttl,aborted}=%v want 1", v)
		}
	})
}

func TestKineTTLDeadHoldSuspectLogAfterCooldownAndExitClear(t *testing.T) {
	e := fixture(t)
	var holdActive atomic.Bool
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetNode: func(context.Context) (map[string]string, []string, error) {
			if holdActive.Load() {
				return map[string]string{nodecond.AnnoClusterMaintenanceUntil: "2099-01-01T00:00:00Z"}, nil, nil
			}
			return nil, nil, nil
		},
	}
	e.MkProc(t, 3055, "kine", []string{"kine"}, 1000)
	e.Journal = "E TTL initial list failed\n"

	// Cycle 1: kill + spend MinRestart budget.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 {
		t.Fatalf("precondition: expected 1 kill, got %v", e.Kills)
	}
	// Cycle 2: cooldown suspect log uses StateKineTTLDead.
	e.H.Cycle(context.Background())
	if n := e.CountLogLines("in restart cooldown"); n != 1 {
		t.Fatalf("cooldown suspect lines=%d want 1", n)
	}

	// +31m (> 30m MinRestart, < 1h SuspectLogCadence) with maintenance active ->
	// must NOT collide with cooldown SuspectLog key.
	e.Now = e.Now.Add(e.H.Cfg.KineTTL.MinRestart + time.Minute)
	holdActive.Store(true)
	e.H.Cycle(context.Background())
	if n := e.CountLogLines("holding kill"); n != 1 {
		t.Fatalf("expected holding kill log after cooldown within SuspectLogCadence, got %d:\n%s", n, e.LogLines())
	}
	if len(e.Kills) != 1 {
		t.Fatalf("killed kine during maintenance hold: %v", e.Kills)
	}

	// Clean respawn exits StateKineTTLDead and clears the -hold suspect budget;
	// a new episode within SuspectLogCadence must emit a fresh holding kill log.
	e.Journal = ""
	if err := os.RemoveAll(filepath.Join(e.Proc, "3055")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3056, "kine", []string{"kine"}, 1000)
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateKineTTLDead) {
		t.Fatal("StateKineTTLDead did not exit on clean kine respawn")
	}

	e.Journal = "E TTL initial list failed\n"
	e.H.Cycle(context.Background())
	if n := e.CountLogLines("holding kill"); n != 2 {
		t.Fatalf("expected fresh holding kill log on new episode, got %d:\n%s", n, e.LogLines())
	}
}
