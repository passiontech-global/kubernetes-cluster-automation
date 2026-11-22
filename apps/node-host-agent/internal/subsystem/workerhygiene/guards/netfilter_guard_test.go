// netfilter_guard_test.go — P2.11 coverage: the per-pid stuck
// confirmation (a pid must qualify NetfilterGuardStuckCycles
// cycles before the kill pass touches it), the flock-based
// xtables.lock wedge streak, the `nft monitor` exclusion and the
// legacy-leak gauge's empty-table-set false-positive guard.
package guards

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// mkNetfilterProc plants /proc/<pid>/stat (+ optional cmdline)
// under the fixture ProcRoot. state is the raw stat state char —
// "D" qualifies regardless of age (kernel-side wedge), "S" needs
// the dir mtime aged past NetfilterGuardHungCmdSec.
func mkNetfilterProc(t *testing.T, d *wdeps.Deps, pid int, comm, state string,
	cmdline []string, age time.Duration) {
	t.Helper()
	mkNetfilterProcStart(t, d, pid, comm, state, cmdline, age, 1)
}

// mkNetfilterProcStart is mkNetfilterProc with an explicit
// starttime (stat field 22, jiffies) — the streak-identity half
// of the (pid,starttime) key, so tests can simulate PID reuse.
func mkNetfilterProcStart(t *testing.T, d *wdeps.Deps, pid int, comm, state string,
	cmdline []string, age time.Duration, start int64) {
	t.Helper()
	pdir := filepath.Join(d.Cfg.ProcRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Fields[19] lands on starttime — pad the tail so the parse
	// sees a realistic 52-field stat tail.
	stat := strconv.Itoa(pid) + " (" + comm + ") " + state +
		" 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 " +
		strconv.FormatInt(start, 10) + " 0 0\n"
	if err := os.WriteFile(filepath.Join(pdir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if cmdline != nil {
		raw := ""
		for _, a := range cmdline {
			raw += a + "\x00"
		}
		if err := os.WriteFile(filepath.Join(pdir, "cmdline"), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if age > 0 {
		old := time.Now().Add(-age)
		if err := os.Chtimes(pdir, old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// nfEnv returns a CycleEnv whose PidsOnce serves the fixture pids
// and marks the worker active — Gated() skips every check
// otherwise.
func nfEnv(pids ...int) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return pids },
	}
}

// nfCheck builds the check over gDeps with the P2.11 knobs pinned:
// interval spacing off (frozen fixture clock), legacy probe off,
// kill path on.
func nfCheck(t *testing.T, d *wdeps.Deps) *NetfilterGuardCheck {
	t.Helper()
	d.Cfg.Wave2.NetfilterGuardIntervalSec = 0 // spacing gate off in tests
	d.Cfg.Wave2.NetfilterGuardLegacyProbe = false
	d.Cfg.Wave2.NetfilterGuardKillEnabled = true
	d.Cfg.Wave2.NetfilterGuardStuckCycles = 2
	d.Cfg.Wave2.NetfilterGuardMaxKillsCycle = 4
	return NewNetfilterGuard(d)
}

func TestNetfilterGuardKillNeedsPerPidConfirmation(t *testing.T) {
	d, f := gDeps(t)
	mkNetfilterProc(t, d, 6101, "iptables", "S", nil, 5*time.Minute)
	c := nfCheck(t, d)
	ctx := context.Background()

	// Cycle 1: the pid qualifies but has not yet reached
	// StuckCycles — the kill pass must not touch it.
	c.Run(ctx, nfEnv(6101))
	if len(f.Kills) != 0 {
		t.Fatalf("cycle 1 killed %d pids — single-cycle evidence "+
			"must never kill", len(f.Kills))
	}
	// Cycle 2: confirmed → bounded SIGKILL + ACTION log.
	c.Run(ctx, nfEnv(6101))
	if len(f.Kills) != 1 || f.Kills[0].PID != 6101 ||
		f.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("cycle 2 kills=%+v want one SIGKILL to 6101", f.Kills)
	}
	// The pid disappears next cycle → its streak resets with it.
	c.Run(ctx, nfEnv())
	if len(c.seen) != 0 {
		t.Fatalf("seen=%v want empty after the pid vanished", c.seen)
	}
}

// TestNetfilterGuardPidReuseResetsStreak pins the (pid,starttime)
// streak identity: pid 7101 qualifies once, dies, and the kernel
// recycles the SAME pid for a fresh iptables — the new process
// must start its confirmation streak from zero, not inherit the
// dead one's and get killed on its first qualifying cycle.
func TestNetfilterGuardPidReuseResetsStreak(t *testing.T) {
	d, f := gDeps(t)
	// First process: starttime=100, qualifies cycle 1.
	mkNetfilterProcStart(t, d, 7101, "iptables", "S", nil, 2*time.Minute, 100)
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	c := nfCheck(t, d)
	ctx := context.Background()

	c.Run(ctx, nfEnv(7101))
	if len(f.Kills) != 0 {
		t.Fatalf("cycle 1 kills=%d want 0 (streak=1 of 2)", len(f.Kills))
	}
	// PID reuse: same pid dir, NEW starttime — the old process is
	// gone, a different one now holds 7101.
	mkNetfilterProcStart(t, d, 7101, "iptables", "S", nil, 2*time.Minute, 999)
	c.Run(ctx, nfEnv(7101))
	if len(f.Kills) != 0 {
		t.Fatalf("cycle 2 kills=%d want 0 — recycled pid must not "+
			"inherit the dead process's streak", len(f.Kills))
	}
	// The NEW process confirms on its own second cycle.
	c.Run(ctx, nfEnv(7101))
	if len(f.Kills) != 1 || f.Kills[0].PID != 7101 {
		t.Fatalf("cycle 3 kills=%+v want one SIGKILL to 7101", f.Kills)
	}
}

func TestNetfilterGuardNftMonitorExcluded(t *testing.T) {
	d, f := gDeps(t)
	// `nft monitor` is the one netfilter comm SUPPOSED to live
	// forever: S-state, ancient, real cmdline — without the
	// exclusion it false-positives every cycle.
	mkNetfilterProc(t, d, 6201, "nft", "S",
		[]string{"nft", "monitor"}, 2*time.Hour)
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	c := nfCheck(t, d)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		c.Run(ctx, nfEnv(6201))
	}
	if len(f.Kills) != 0 {
		t.Fatalf("nft monitor killed: %+v", f.Kills)
	}
	if len(c.seen) != 0 {
		t.Fatalf("nft monitor accumulated streaks: %+v", c.seen)
	}
}

func TestNetfilterGuardStaleSStateCounts(t *testing.T) {
	d, f := gDeps(t)
	// The counterpart to the nft-monitor exclusion: an S-state
	// iptables parked past HungCmdSec IS the flock()-blocked
	// wedge signature — S is not a safe state for a netfilter
	// tool.
	mkNetfilterProc(t, d, 6301, "iptables", "S", nil, 2*time.Hour)
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	c := nfCheck(t, d)
	c.Run(context.Background(), nfEnv(6301))
	c.Run(context.Background(), nfEnv(6301))
	if len(f.Kills) != 1 {
		t.Fatalf("stale S-state iptables kills=%d want 1", len(f.Kills))
	}
}

func TestNetfilterGuardLockWedgeLatch(t *testing.T) {
	d, _ := gDeps(t)
	// A real held flock on the host xtables.lock — the check's
	// LOCK_NB probe must read EWOULDBLOCK three cycles running.
	runDir := t.TempDir()
	lockPath := filepath.Join(runDir, "xtables.lock")
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(lockPath, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("test could not take the lock: %v", err)
	}
	d.Cfg.Disk.HostRunDir = runDir
	d.Cfg.Wave2.NetfilterGuardLockPath = "" // derive from HostRunDir
	c := nfCheck(t, d)
	ctx := context.Background()

	c.Run(ctx, nfEnv())
	c.Run(ctx, nfEnv())
	if c.lockStreak != 2 {
		t.Fatalf("lockStreak=%d want 2 before the latch bound",
			c.lockStreak)
	}
	c.Run(ctx, nfEnv())
	if c.lockStreak < netfilterLockStreakCycles {
		t.Fatalf("lockStreak=%d want >= %d", c.lockStreak,
			netfilterLockStreakCycles)
	}
	if _, err := os.Stat(filepath.Join(d.Cfg.WatchdogStateDir,
		"state-"+latchdefs.LatchNetfilterLocked)); err != nil {
		t.Fatalf("state-%s latch file missing: %v",
			latchdefs.LatchNetfilterLocked, err)
	}
}

func TestNetfilterGuardLockReleasedClears(t *testing.T) {
	d, _ := gDeps(t)
	runDir := t.TempDir()
	lockPath := filepath.Join(runDir, "xtables.lock")
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(lockPath, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	d.Cfg.Disk.HostRunDir = runDir
	c := nfCheck(t, d)
	ctx := context.Background()
	c.Run(ctx, nfEnv())
	c.Run(ctx, nfEnv())
	c.Run(ctx, nfEnv())
	if c.lockStreak < netfilterLockStreakCycles {
		t.Fatalf("setup: lockStreak=%d want latched", c.lockStreak)
	}
	// Release the holder — the next probe acquires cleanly and the
	// streak resets.
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	c.Run(ctx, nfEnv())
	if c.lockStreak != 0 {
		t.Fatalf("lockStreak=%d want 0 after release", c.lockStreak)
	}
}

func TestNetfilterGuardLegacyGaugeEmptyNames(t *testing.T) {
	d, _ := gDeps(t)
	// /proc/1/net/ip_tables_names absent → the legacy table set is
	// empty → the gauge is DEFINITIVELY 0, never a fabricated
	// nonzero from a save that cannot run in tests anyway.
	c := nfCheck(t, d)
	d.Cfg.Wave2.NetfilterGuardLegacyProbe = true // nfCheck pins it off
	c.Run(context.Background(), nfEnv())
	if got := d.Series.IPTablesLegacyLeakedRules; got != 0 {
		t.Fatalf("IPTablesLegacyLeakedRules=%d want 0 with no "+
			"ip_tables_names", got)
	}
}

func TestNetfilterGuardSkipsZombieAndRunnable(t *testing.T) {
	d, f := gDeps(t)
	d.Cfg.Wave2.NetfilterGuardStuckCycles = 1
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	mkNetfilterProc(t, d, 301, "iptables", "Z", nil, 5*time.Minute)
	mkNetfilterProc(t, d, 302, "iptables", "R", nil, 5*time.Minute)
	mkNetfilterProc(t, d, 303, "iptables", "S", nil, 5*time.Minute)
	old := f.Now.Add(-5 * time.Minute)
	for _, pid := range []int{301, 302, 303} {
		_ = os.Chtimes(filepath.Join(d.Cfg.ProcRoot, strconv.Itoa(pid)), old, old)
	}
	c := nfCheck(t, d)
	d.Cfg.Wave2.NetfilterGuardStuckCycles = 1
	c.Run(context.Background(), nfEnv(301, 302, 303))
	if len(f.Kills) != 1 || f.Kills[0].PID != 303 {
		t.Fatalf("kills=%+v want only PID 303 (skipped Z/R)", f.Kills)
	}
}

func TestNetfilterGuardUsrSbinNftMonitorExcluded(t *testing.T) {
	d, f := gDeps(t)
	mkNetfilterProc(t, d, 6202, "nft", "S",
		[]string{"/usr/sbin/nft", "monitor"}, 2*time.Hour)
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	c := nfCheck(t, d)
	c.Run(context.Background(), nfEnv(6202))
	c.Run(context.Background(), nfEnv(6202))
	if len(f.Kills) != 0 || len(c.seen) != 0 {
		t.Fatalf("/usr/sbin/nft monitor was not excluded: kills=%+v seen=%+v", f.Kills, c.seen)
	}
}

func TestNetfilterGuardDStateNotKilled(t *testing.T) {
	d, f := gDeps(t)
	mkNetfilterProc(t, d, 6203, "iptables", "D", nil, 0)
	c := nfCheck(t, d)
	c.Run(context.Background(), nfEnv(6203))
	c.Run(context.Background(), nfEnv(6203))
	if len(f.Kills) != 0 {
		t.Fatalf("D-state iptables must not be SIGKILLed: %+v", f.Kills)
	}
	if !strings.Contains(f.LogLines(t), "uninterruptible D-state") {
		t.Fatalf("missing D-state suspect log:\n%s", f.LogLines(t))
	}
}

func TestNetfilterGuardPidReuseMidCyclePreventsKill(t *testing.T) {
	d, f := gDeps(t)
	mkNetfilterProcStart(t, d, 6204, "iptables", "S", nil, 2*time.Minute, 111)
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	c := nfCheck(t, d)
	d.Cfg.Wave2.NetfilterGuardStuckCycles = 1
	d.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return f.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			// Simulate PID reuse mid-cycle between scanStuck and KillFn.
			mkNetfilterProcStart(t, d, 6204, "iptables", "S", nil, 2*time.Minute, 222)
			return map[string]string{}, nil
		},
	}
	c.Run(context.Background(), nfEnv(6204))
	if len(f.Kills) != 0 {
		t.Fatalf("PID reuse mid-cycle must abort SIGKILL: %+v", f.Kills)
	}
}

func TestNetfilterGuardHoldEmergencyHeal(t *testing.T) {
	// 1. Active maintenance holds SIGKILL.
	d, f := gDeps(t)
	mkNetfilterProc(t, d, 6205, "iptables", "S", nil, 5*time.Minute)
	c := nfCheck(t, d)
	d.Cfg.Wave2.NetfilterGuardStuckCycles = 1
	d.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return f.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			return map[string]string{nodecond.KuredLockAnno: `{"nodeID":"node-a"}`}, nil
		},
	}
	c.Run(context.Background(), nfEnv(6205))
	if len(f.Kills) != 0 {
		t.Fatalf("HoldEmergencyHeal did not block SIGKILL under kured lock: %+v", f.Kills)
	}

	// 2. API outage fails OPEN for HoldEmergencyHeal so netfilter recovery still runs.
	d2, f2 := gDeps(t)
	mkNetfilterProc(t, d2, 6206, "iptables", "S", nil, 5*time.Minute)
	c2 := nfCheck(t, d2)
	d2.Cfg.Wave2.NetfilterGuardStuckCycles = 1
	d2.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return f2.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			return nil, errors.New("apiserver unreachable")
		},
	}
	c2.Run(context.Background(), nfEnv(6206))
	if len(f2.Kills) != 1 || f2.Kills[0].PID != 6206 {
		t.Fatalf("HoldEmergencyHeal must fail open on API error; kills=%+v", f2.Kills)
	}
}

func TestNetfilterGuardPidsOKFalseAndProcErrorPreserveStreak(t *testing.T) {
	d, f := gDeps(t)
	mkNetfilterProc(t, d, 6210, "iptables", "S", nil, 5*time.Minute)
	c := nfCheck(t, d)
	ctx := context.Background()

	// Cycle 1: builds confirmation streak = 1.
	c.Run(ctx, &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{6210} },
		PidsOK:       func() bool { return true },
	})
	if got := testutil.ToFloat64(d.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1", got)
	}
	if len(c.seen) != 1 || len(f.Kills) != 0 {
		t.Fatalf("unexpected cycle 1 state: seen=%+v kills=%+v", c.seen, f.Kills)
	}

	// PidsOnce() == nil + PidsOK() == false must abort "inconclusive" and preserve c.seen.
	c.Run(ctx, &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return nil },
		PidsOK:       func() bool { return false },
	})
	if got := testutil.ToFloat64(d.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive cycles=%v want 1", got)
	}
	if len(c.seen) != 1 {
		t.Fatalf("c.seen wiped on PidsOK()=false: %+v", c.seen)
	}

	// PidsOnce == nil + Proc.PIDs() error must also abort "inconclusive" and preserve c.seen.
	d.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
	c.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := testutil.ToFloat64(d.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "inconclusive")); got != 2 {
		t.Fatalf("inconclusive cycles=%v want 2", got)
	}
	if len(c.seen) != 1 || len(f.Kills) != 0 {
		t.Fatalf("unexpected state after Proc.PIDs error: seen=%+v kills=%+v", c.seen, f.Kills)
	}

	// Recovery cycle: preserved streak=1 immediately confirms & kills on cycle 2.
	d.Proc = procfs.New(f.ProcDir)
	c.Run(ctx, nfEnv(6210))
	if len(f.Kills) != 1 || f.Kills[0].PID != 6210 {
		t.Fatalf("kills=%+v want SIGKILL on 6210 on preserved streak=2", f.Kills)
	}
}

func TestNetfilterGuardUsesStatsOnceAndKeepsTOCTOU(t *testing.T) {
	d, f := gDeps(t)
	d.Cfg.Wave2.NetfilterGuardStuckCycles = 1
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	mkNetfilterProcStart(t, d, 6302, "iptables", "S", nil, 2*time.Minute, 100)

	statsCalls := 0
	statsSnap := map[int]procfs.Stat{
		6301: {HasComm: true, Comm: "bash", Fields: []string{"S", "1"}}, // no /proc/6301/stat on disk
		6302: {HasComm: true, Comm: "iptables", Fields: []string{"S", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "100"}},
	}
	c := nfCheck(t, d)
	// Mutate /proc/6302/stat starttime between scanStuck and KillFn to confirm live TOCTOU check.
	d.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return f.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			mkNetfilterProcStart(t, d, 6302, "iptables", "S", nil, 2*time.Minute, 200)
			return map[string]string{}, nil
		},
	}
	c.Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{6301, 6302} },
		PidsOK:       func() bool { return true },
		StatsOnce: func() map[int]procfs.Stat {
			statsCalls++
			return statsSnap
		},
	})
	if statsCalls != 1 {
		t.Fatalf("StatsOnce called %d times, want 1", statsCalls)
	}
	if len(f.Kills) != 0 {
		t.Fatalf("live TOCTOU must abort kill on starttime change even with StatsOnce; kills=%+v", f.Kills)
	}

	// Verify StatsOnce omitting a 0o000 stat PID still aborts via statNonENOENT.
	if os.Geteuid() != 0 {
		mkNetfilterProcStart(t, d, 6303, "iptables", "S", nil, 2*time.Minute, 300)
		stat6303 := filepath.Join(f.ProcDir, "6303", "stat")
		if err := os.Chmod(stat6303, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(stat6303, 0o644) })
		c.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6301, 6303} },
			PidsOK:       func() bool { return true },
			StatsOnce: func() map[int]procfs.Stat {
				statsCalls++
				return statsSnap
			},
		})
		if statsCalls != 2 {
			t.Fatalf("StatsOnce called %d times, want 2", statsCalls)
		}
		if got := testutil.ToFloat64(d.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1 when StatsOnce omits 0o000 stat PID", got)
		}
	}
}

func TestProbeLegacyRules(t *testing.T) {
	cases := []struct {
		name    string
		initial int64
		setup   func(t *testing.T, d *wdeps.Deps, f *wdepstest.Fixture, namesPath string)
		want    int64
	}{
		{
			name:    "enoent_sets_zero",
			initial: 7,
			setup:   func(_ *testing.T, _ *wdeps.Deps, _ *wdepstest.Fixture, _ string) {},
			want:    0,
		},
		{
			name:    "non_enoent_read_error_preserves_gauge",
			initial: 7,
			setup: func(t *testing.T, _ *wdeps.Deps, _ *wdepstest.Fixture, namesPath string) {
				// Directory at namesPath fails os.ReadFile with EISDIR even when running as root.
				if err := os.MkdirAll(namesPath, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: 7,
		},
		{
			name:    "whitespace_only_names_sets_zero",
			initial: 7,
			setup: func(_ *testing.T, _ *wdeps.Deps, _ *wdepstest.Fixture, namesPath string) {
				wdepstest.WriteFile(t, namesPath, "  \n\t \n")
			},
			want: 0,
		},
		{
			name:    "systemd_nil_preserves_gauge",
			initial: 7,
			setup: func(_ *testing.T, d *wdeps.Deps, _ *wdepstest.Fixture, namesPath string) {
				wdepstest.WriteFile(t, namesPath, "filter\n")
				d.Cfg.Systemd = nil
			},
			want: 7,
		},
		{
			name:    "exec_bounded_error_preserves_gauge",
			initial: 7,
			setup: func(_ *testing.T, _ *wdeps.Deps, _ *wdepstest.Fixture, namesPath string) {
				wdepstest.WriteFile(t, namesPath, "filter\n")
				// iptables-legacy-save omitted from f.SDReply -> returns ENOENT error.
			},
			want: 7,
		},
		{
			name:    "counts_dash_a_lines_ignoring_chains_comments_counters",
			initial: 7,
			setup: func(_ *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture, namesPath string) {
				wdepstest.WriteFile(t, namesPath, "filter\nnat\n")
				f.SDReply["iptables-legacy-save"] = strings.Join([]string{
					"# Generated by iptables-save",
					"*filter",
					":INPUT ACCEPT [12:345]",
					":KUBE-SERVICES - [0:0]",
					"[0:0] -A COUNTER_PREFIX",
					"  -A INDENTED_NOT_COUNTED",
					"-A INPUT -j ACCEPT",
					"-A FORWARD -j KUBE-SERVICES",
					"COMMIT",
					"*nat",
					"-A PREROUTING -j KUBE-SERVICES",
					"COMMIT",
				}, "\n")
			},
			want: 3,
		},
		{
			name:    "valid_output_without_rules_resets_to_zero",
			initial: 7,
			setup: func(_ *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture, namesPath string) {
				wdepstest.WriteFile(t, namesPath, "filter\n")
				f.SDReply["iptables-legacy-save"] = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
			},
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, f := gDeps(t)
			c := nfCheck(t, d)
			d.Series.IPTablesLegacyLeakedRules = tc.initial
			namesPath := filepath.Join(d.Cfg.ProcRoot, "1", "net", "ip_tables_names")
			tc.setup(t, d, f, namesPath)
			c.probeLegacyRules(context.Background())
			if got := d.Series.IPTablesLegacyLeakedRules; got != tc.want {
				t.Fatalf("IPTablesLegacyLeakedRules=%d want %d", got, tc.want)
			}
		})
	}
}
