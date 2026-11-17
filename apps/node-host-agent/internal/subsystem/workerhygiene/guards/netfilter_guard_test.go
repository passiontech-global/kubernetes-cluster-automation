// netfilter_guard_test.go — P2.11 coverage: the per-pid stuck
// confirmation (a pid must qualify NetfilterGuardStuckCycles
// cycles before the kill pass touches it), the flock-based
// xtables.lock wedge streak, the `nft monitor` exclusion and the
// legacy-leak gauge's empty-table-set false-positive guard.
package guards

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
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
	mkNetfilterProc(t, d, 6101, "iptables", "D", nil, 0)
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
	mkNetfilterProcStart(t, d, 7101, "iptables", "D", nil, 0, 100)
	d.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
	c := nfCheck(t, d)
	ctx := context.Background()

	c.Run(ctx, nfEnv(7101))
	if len(f.Kills) != 0 {
		t.Fatalf("cycle 1 kills=%d want 0 (streak=1 of 2)", len(f.Kills))
	}
	// PID reuse: same pid dir, NEW starttime — the old process is
	// gone, a different one now holds 7101.
	mkNetfilterProcStart(t, d, 7101, "iptables", "D", nil, 0, 999)
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
