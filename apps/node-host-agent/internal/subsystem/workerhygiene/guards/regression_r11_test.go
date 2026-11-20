package guards_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR11DstateCheckPartialEACCESWithPID1ReadablePreservesLatchAndFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.MkStatProc(t, 1, "systemd", "S", "")
	e.MkStatProc(t, 1001, "runc", "D", "")
	e.MkStatProc(t, 1002, "containerd", "D", "")

	// Cycles 1-2 arm LatchDStateStorm.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("setup: LatchDStateStorm not armed")
	}

	// PID 1 remains readable (readOK >= 1), while D-state PIDs return EACCES -> must abort and preserve latch.
	for _, pid := range []string{"1001", "1002"} {
		p := filepath.Join(e.ProcDir, pid, "stat")
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	}
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDState, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("LatchDStateStorm falsely exited on partial EACCES when PID 1 was readable")
	}

	// Restore healthy S-state -> exits LatchDStateStorm cleanly.
	for _, pid := range []string{"1001", "1002"} {
		if err := os.Chmod(filepath.Join(e.ProcDir, pid, "stat"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.MkStatProc(t, 1001, "runc", "S", "")
	e.MkStatProc(t, 1002, "containerd", "S", "")
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("LatchDStateStorm did not exit after recovery")
	}

	// Also verify pending streak preservation across partial EACCES (fails=1 -> EACCES -> D-state arms immediately).
	e.MkStatProc(t, 1001, "runc", "D", "")
	e.MkStatProc(t, 1002, "containerd", "D", "")
	e.H.Cycle(context.Background()) // fails=1
	if e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("unexpected latch on cycle 1")
	}
	for _, pid := range []string{"1001", "1002"} {
		if err := os.Chmod(filepath.Join(e.ProcDir, pid, "stat"), 0o000); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background()) // abort=2, fails stays 1
	for _, pid := range []string{"1001", "1002"} {
		if err := os.Chmod(filepath.Join(e.ProcDir, pid, "stat"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background()) // fails=2 -> arms
	if !e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("pending fails streak was wiped during partial EACCES")
	}

	// ENOENT-only exited PIDs still exit cleanly when PID 1 is readable.
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "1001"))
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "1002"))
	e.H.Check(wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{1, 1001, 1002} },
		PidsOK:       func() bool { return true },
	})
	if e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("expected ENOENT-only exited PIDs to clear LatchDStateStorm")
	}
}

func TestR11ZombieStormPartialEACCESWithPID1ReadablePreservesLatchAndStreaks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.H.Cfg.Pressure.ZombieStormThreshold = 1
	e.MkStatProc(t, 1, "systemd", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2000", "stat"),
		"2000 (parent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 111 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2001", "stat"),
		"2001 (z1) Z 2000 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 112 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2002", "stat"),
		"2002 (z2) Z 2000 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 113 0 0\n")

	// Cycles 1-2 arm LatchZombieStorm.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("setup: LatchZombieStorm not armed")
	}
	if n := strings.Count(e.LogLines(t), "ACTION zombie-storm:"); n != 1 {
		t.Fatalf("setup ACTION count=%d want 1", n)
	}

	// PID 1 remains readable (readOK >= 1), while zombie/parent PIDs return EACCES -> must abort, keep latch and streaks.
	for _, pid := range []string{"2000", "2001", "2002"} {
		p := filepath.Join(e.ProcDir, pid, "stat")
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	}
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckZombieStorm, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("LatchZombieStorm falsely exited on partial EACCES when PID 1 was readable")
	}

	// Restore stats while zombies persist: streak was preserved (> ConsecNeeded), so NO duplicate ACTION line.
	for _, pid := range []string{"2000", "2001", "2002"} {
		if err := os.Chmod(filepath.Join(e.ProcDir, pid, "stat"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("LatchZombieStorm exited while zombies persisted after recovery")
	}
	if n := strings.Count(e.LogLines(t), "ACTION zombie-storm:"); n != 1 {
		t.Fatalf("ACTION count=%d want 1 (streaks were wiped during partial EACCES)", n)
	}

	// Zombies exit (ENOENT) -> clears LatchZombieStorm cleanly.
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "2001"))
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "2002"))
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("LatchZombieStorm did not exit after zombies exited")
	}
}
