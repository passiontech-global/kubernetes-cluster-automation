package ctr_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- reaper failure tails and fail-closed gates ---

// wedgedTaskDir builds a hex-id task dir whose init is dead; when
// withRootfs is set the bundle rootfs subtree exists (a live mount).
func wedgedTaskDir(t *testing.T, e *env, id string, withRootfs bool) string {
	t.Helper()
	dir := filepath.Join(e.CtrDir, id)
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77888")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	if withRootfs {
		wdepstest.WriteFile(t, filepath.Join(dir, "rootfs", "bin", "sh"), "#!/bin/sh\n")
	}
	return dir
}

// TestCtrTasksUmountFailureStillRemoves: a failed lazy umount is
// logged and the removal is still attempted (best effort).
func TestCtrTasksUmountFailureStillRemoves(t *testing.T) {
	e := fixture(t)
	// No SDReply["umount"] → the exec fails.
	dir := wedgedTaskDir(t, e, strings.Repeat("4", 64), true)
	e.H.Cycle(context.Background()) // marker only
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm → umount fails → rm anyway
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir kept after the failed umount — removal must still run")
	}
	if !strings.Contains(e.LogLines(t), "umount -l "+filepath.Join(dir, "rootfs")+" failed") {
		t.Fatalf("missing umount-failure line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksRmFailureLogged: an undeletable dir logs the suspect
// instead of silently losing the task.
func TestCtrTasksRmFailureLogged(t *testing.T) {
	e := fixture(t)
	dir := wedgedTaskDir(t, e, strings.Repeat("5", 64), false)
	e.H.Cycle(context.Background())
	e.Now = e.Now.Add(6 * time.Minute)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "rm task dir ") {
		t.Fatalf("missing rm-failure suspect line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksOrphanShimKillFailureLogged: a failing signal delivery
// must not read as a successful reap.
func TestCtrTasksOrphanShimKillFailureLogged(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("8", 64)
	e.MkProc(t, 9350, "S",
		"containerd-shim-runc-v2\x00-id\x00"+sid+
			"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
	old := e.Now.Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9350"), old, old); err != nil {
		t.Fatal(err)
	}
	orig := e.H.Cfg.Seams.Host.KillFn
	e.H.Cfg.Seams.Host.KillFn = func(pid int, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			return errors.New("permission denied")
		}
		return orig(pid, sig)
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "kill orphan shim pid=9350 failed") {
		t.Fatalf("missing shim-kill failure line:\n%s", e.LogLines(t))
	}
	if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) &&
		strings.Contains(e.LogLines(t), "escalated") {
		t.Fatal("unexpected escalation on a kill-shaped failure")
	}
}

// TestCtrTasksOrphanShimDStateEscalates: an orphan shim wedged in D
// cannot be SIGKILLed away — the wedge escalates into the shared
// pod-teardown latch instead of a doomed kill.
func TestCtrTasksOrphanShimDStateEscalates(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("6", 64)
	e.MkProc(t, 9360, "D",
		"containerd-shim-runc-v2\x00-id\x00"+sid+
			"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
	old := e.Now.Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9360"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
		t.Fatal("D-state orphan shim not escalated to pod-teardown-wedged")
	}
	if !strings.Contains(e.LogLines(t), "escalated to pod-teardown-wedged") {
		t.Fatalf("missing escalation line:\n%s", e.LogLines(t))
	}
	for _, k := range e.Kills {
		if k.PID == 9360 {
			t.Fatal("D-state shim SIGKILLed anyway — the signal pends forever")
		}
	}
}

// TestCtrTasksInitKillFailureLogged: the live-init kill failing is
// evidence, not silence.
func TestCtrTasksInitKillFailureLogged(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 77777, "S", "", "")
	dir := filepath.Join(e.CtrDir, strings.Repeat("7", 64))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77777")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(6 * time.Minute)
	orig := e.H.Cfg.Seams.Host.KillFn
	e.H.Cfg.Seams.Host.KillFn = func(pid int, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			return errors.New("permission denied")
		}
		return orig(pid, sig)
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "kill init 77777 of ") {
		t.Fatalf("missing init-kill failure line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksOrphanSandboxCapLine: a zero clean budget logs the
// pending-cap suspect instead of touching sandbox dirs.
func TestCtrTasksOrphanSandboxCapLine(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MaxTaskClean = 0
	sid := strings.Repeat("2", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	wdepstest.WriteFile(t, filepath.Join(sbDir, "junk"), "x")
	old := e.Now.Add(-45 * time.Minute)
	if err := os.Chtimes(sbDir, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background()) // confirmed → cap 0
	if !strings.Contains(e.LogLines(t), "orphan sandbox dir still pending cap=0") {
		t.Fatalf("missing sandbox cap line:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir removed despite the zero budget")
	}
}

// TestCtrTasksSandboxMarkerPruned: sandbox markers whose dir
// disappeared are swept between runs.
func TestCtrTasksSandboxMarkerPruned(t *testing.T) {
	e := fixture(t)
	gone := "sandbox-orphan-seen-" + strings.Repeat("3", 64)
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, gone), "stale")
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, gone)); !os.IsNotExist(err) {
		t.Fatal("stale sandbox marker survived the sweep")
	}
}

// TestCtrImagesAPIFailAborts: no apiserver verdict → the healer never
// removes an image; a clean round initializes its ledger.
func TestCtrImagesAPIFailAborts(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "rm") {
			removed = append(removed, strings.Join(argv, " "))
		}
		return nil
	}
	c := wdepstest.Check[*ctr.CtrImagesCheck](e.H, wdeps.CheckCtrImages)
	c.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if len(removed) != 0 {
		t.Fatalf("images removed with the API down: %v", removed)
	}
	c.Run(context.Background(), &wdeps.CycleEnv{APIOK: true, WorkerActive: true})
}

// TestCtrTasksGatesAndPrunes: the worker gate stands the reaper down;
// an unreadable task root aborts; markers and non-dir entries on the
// task root are handled without touching processes.
func TestCtrTasksGatesAndPrunes(t *testing.T) {
	// Worker gate down → no task-root walk at all.
	e := fixture(t)
	e.H.Cfg.Seams.Host.KillFn = func(int, syscall.Signal) error {
		t.Error("kill ran with the worker gate down")
		return nil
	}
	wdepstest.Check[*ctr.CtrTasksCheck](e.H, wdeps.CheckCtrTasks).
		Run(context.Background(), &wdeps.CycleEnv{})

	// Unreadable task root → skip, never verdict.
	e = fixture(t)
	e.H.Cfg.CtrTaskRoot = filepath.Join(e.CtrDir, "gone")
	wdepstest.Check[*ctr.CtrTasksCheck](e.H, wdeps.CheckCtrTasks).
		Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if !strings.Contains(e.LogLines(t), "ctr-tasks check skipped") {
		t.Fatalf("missing unreadable-root line:\n%s", e.LogLines(t))
	}

	// A non-dir entry on the task root is not a task.
	e = fixture(t)
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "not-a-task"), "x")
	// A wedged-seen marker whose dir disappeared is swept.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir,
		"wedged-seen-"+strings.Repeat("0", 64)), "gone")
	// A fresh (<5m) wedge marker defers the confirmation: the first
	// Cycle arms it, the immediate second Cycle must not confirm.
	freshID := strings.Repeat("f", 64)
	wedgedTaskDir(t, e, freshID, false)
	e.H.Cycle(context.Background()) // arm
	e.H.Cycle(context.Background()) // sub-5m → deferred
	if strings.Contains(e.LogLines(t), "ACTION: rm wedged task dir") {
		t.Fatal("confirmed on a sub-5m marker")
	}
}

// TestCtrTasksShimKillCap: MaxShimKill bounds the orphan sweep — the
// unexamined tail keeps the incomplete-scan flag instead of a verdict.
func TestCtrTasksShimKillCap(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MaxShimKill = 2
	old := e.Now.Add(-10 * time.Minute)
	for i := range 4 {
		pid := 9370 + i
		sid := fmt.Sprintf("%064x", i+10)
		e.MkProc(t, pid, "S",
			"containerd-shim-runc-v2\x00-id\x00"+sid+
				"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
		if err := os.Chtimes(filepath.Join(e.ProcDir, strconv.Itoa(pid)), old, old); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 2 {
		t.Fatalf("kills=%d want exactly MaxShimKill=2", len(e.Kills))
	}
}

// TestCtrTasksLeftoverHolderKilled: a live process holding the wedged
// task id on its cmdline is SIGKILLed before the dir removal — the
// pkill -9 -f parity.
func TestCtrTasksLeftoverHolderKilled(t *testing.T) {
	e := fixture(t)
	id := strings.Repeat("d", 64)
	dir := wedgedTaskDir(t, e, id, false)
	// A shim leftover still holding the task id.
	e.MkProc(t, 9399, "S",
		"containerd-shim-runc-v2\x00-id\x00"+id+
			"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm → kill holder + rm
	killed := false
	for _, k := range e.Kills {
		if k.PID == 9399 && k.Sig == syscall.SIGKILL {
			killed = true
		}
	}
	if !killed {
		t.Fatalf("leftover holder not killed: kills=%v", e.Kills)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir kept after the holder kill")
	}
}

// TestCtrTasksSandboxGatesAndFailures: a young confirmation marker
// defers the removal; an undeletable sandbox dir logs the failure.
func TestCtrTasksSandboxGatesAndFailures(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("1", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	wdepstest.WriteFile(t, filepath.Join(sbDir, "junk"), "x")
	old := e.Now.Add(-45 * time.Minute)
	if err := os.Chtimes(sbDir, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(10 * time.Minute)
	e.H.Cycle(context.Background()) // marker only 10m old → defer
	if strings.Contains(e.LogLines(t), "rm orphan sandbox dir") {
		t.Fatal("sandbox dir removed on a sub-30m marker")
	}
	e.Now = e.Now.Add(25 * time.Minute) // marker 35m → confirm
	if err := os.Chmod(sbDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sbDir, 0o755) })
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "rm orphan sandbox dir ") {
		t.Fatalf("missing sandbox rm-failure line:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir vanished despite the failing removal")
	}
}

// TestCtrImagesGatedAndLedgerInit: the worker gate stands the healer
// down; a bare check round initializes the exec-format ledger.
func TestCtrImagesGatedAndLedgerInit(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Ctr.Exec = func(context.Context, ...string) error {
		t.Error("image rm ran with the worker gate down")
		return nil
	}
	wdepstest.Check[*ctr.CtrImagesCheck](e.H, wdeps.CheckCtrImages).
		Run(context.Background(), &wdeps.CycleEnv{})
}
