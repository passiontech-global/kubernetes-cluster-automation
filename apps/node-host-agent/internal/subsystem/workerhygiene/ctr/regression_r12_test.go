package ctr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR12LoopHygieneProcMountinfoEACCESDoesNotDetachAndAborts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.H.Cfg.Wave3.LoopGCEnabled = true
	sysBlock := t.TempDir()
	e.H.Cfg.Wave3.SysBlockDir = sysBlock
	loopDir := filepath.Join(sysBlock, "loop0")
	if err := os.MkdirAll(filepath.Join(loopDir, "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(loopDir, "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(loopDir, "loop", "autoclear"), "0\n")
	wdepstest.WriteFile(t, filepath.Join(loopDir, "loop", "backing_file"), "/var/lib/img.raw (deleted)\n")

	hostDev := t.TempDir()
	e.H.Cfg.Wave3.HostDevDir = hostDev
	wdepstest.WriteFile(t, filepath.Join(hostDev, "loop0"), "")

	e.H.Cfg.MountinfoFile = filepath.Join(e.ProcDir, "1", "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 0:1 / / rw - ext4 /dev/vda1 rw\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "500", "mountinfo"), "2 1 7:0 / /mnt/c rw - ext4 /dev/loop0 rw\n")
	mi500 := filepath.Join(e.ProcDir, "500", "mountinfo")
	if err := os.Chmod(mi500, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mi500, 0o644) })

	marker := filepath.Join(e.StateDir, "loop-seen-loop0")
	wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-45*time.Minute).Unix()))

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(_ context.Context, dev string) error {
		detached = append(detached, dev)
		return nil
	}

	chk := e.H.Check(wdeps.CheckMountinfo)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{1, 500} },
		PidsOK:       func() bool { return true },
	}
	chk.Run(context.Background(), ce)
	if len(detached) != 0 {
		t.Fatalf("falsely detached in-use loop device %v when /proc/500/mountinfo returned EACCES", detached)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("loop-seen-loop0 marker wiped on abort: %v", err)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckMountinfo, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}

	// Restore mountinfo showing /dev/loop0 mounted -> no detach, prunes stale marker.
	if err := os.Chmod(mi500, 0o644); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), ce)
	if len(detached) != 0 {
		t.Fatalf("detached mounted loop device after recovery: %v", detached)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected loop-seen-loop0 marker pruned once mounted: err=%v", err)
	}
}

func TestR12CtrMetaShimAndTaskDirEACCESPreservesLatch(t *testing.T) {
	setupShim := func(t *testing.T) (*env, *ctr.CtrMetaCheck, *wdeps.CycleEnv, string, string) {
		t.Helper()
		e := fixture(t)
		id := strings.Repeat("b", 64)
		orphanShim(t, e, 9010, id, "/run/k0s/containerd.sock", 20*time.Minute)
		taskDir := filepath.Join(filepath.Dir(e.CtrDir), "k8s.io", id)
		e.MkProc(t, 9011, "S", "", "")
		e.Live[9011] = true
		wdepstest.WriteFile(t, filepath.Join(taskDir, "init.pid"), "9011\n")
		old := e.Now.Add(-20 * time.Minute)
		if err := os.Chtimes(taskDir, old, old); err != nil {
			t.Fatal(err)
		}
		e.H.State.Enter(latchdefs.LatchContainerdCorrupt, "prior")
		chk := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{9010, 9011} },
			PidsOK:       func() bool { return true },
			JournalOnce:  func() string { return "" },
			JournalOK:    func() bool { return true },
		}
		return e, chk, ce, filepath.Join(e.ProcDir, "9010"), taskDir
	}

	t.Run("shim_cmdline_0000_preserves_latch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, chk, ce, shimProc, _ := setupShim(t)
		cmdPath := filepath.Join(shimProc, "cmdline")
		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })

		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
			t.Fatal("LatchContainerdCorrupt cleared when shim cmdline returned EACCES")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		_ = os.Chmod(cmdPath, 0o644)
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
			t.Fatal("LatchContainerdCorrupt did not exit after shim cmdline recovered")
		}
	})

	t.Run("shim_stat_0000_preserves_latch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, chk, ce, shimProc, _ := setupShim(t)
		statPath := filepath.Join(shimProc, "stat")
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
			t.Fatal("LatchContainerdCorrupt cleared when shim stat returned EACCES")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})

	t.Run("task_root_0444_stat_EACCES_preserves_latch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0444 does not block root")
		}
		e, chk, ce, _, taskDir := setupShim(t)
		k8sRoot := filepath.Dir(taskDir)
		if err := os.Chmod(k8sRoot, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(k8sRoot, 0o755) })

		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
			t.Fatal("LatchContainerdCorrupt cleared when task root 0o444 caused os.Stat(taskDir) EACCES")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}

func TestR12HungRuncCmdlineAndPartialStatEACCES(t *testing.T) {
	t.Run("cmdline_0000_on_second_cycle_preserves_streak_and_aborts", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := hungEnv(t, 2)
		e.MkStatProc(t, 7910, "runc", "S", "futex_wait")
		cmdPath := filepath.Join(e.ProcDir, "7910", "cmdline")
		wdepstest.WriteFile(t, cmdPath, "runc\x00create\x00cid\x00")
		ageProc(t, e, 7910, 10*time.Minute)

		chk := hungCheck(e)
		ctx := context.Background()
		chk.Run(ctx, cycleEnv()) // streak=1

		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })
		chk.Run(ctx, cycleEnv()) // abort, preserves streak=1
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckHungRunc, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected kill during cmdline EACCES: %+v", e.Kills)
		}

		if err := os.Chmod(cmdPath, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(ctx, cycleEnv()) // streak=2 -> kills 7910
		if len(e.Kills) != 1 || e.Kills[0].PID != 7910 {
			t.Fatalf("kills=%+v want PID 7910 killed from preserved streak", e.Kills)
		}
	})

	t.Run("partial_stat_0000_with_other_runc_readable_preserves_streak", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := hungEnv(t, 2)
		for _, pid := range []int{7911, 7912} {
			e.MkStatProc(t, pid, "runc", "S", "futex_wait")
			wdepstest.WriteFile(t, filepath.Join(e.ProcDir, fmt.Sprint(pid), "cmdline"), "runc\x00create\x00cid\x00")
			ageProc(t, e, pid, 10*time.Minute)
		}
		chk := hungCheck(e)
		ctx := context.Background()
		chk.Run(ctx, cycleEnv()) // both at streak=1

		stat7911 := filepath.Join(e.ProcDir, "7911", "stat")
		if err := os.Chmod(stat7911, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(stat7911, 0o644) })
		chk.Run(ctx, cycleEnv()) // 7912 killed; 7911 unreadable -> abort & streak preserved
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckHungRunc, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if len(e.Kills) != 1 || e.Kills[0].PID != 7912 {
			t.Fatalf("kills=%+v want 7912 killed", e.Kills)
		}

		// Recover 7911/stat and remove 7912 -> 7911 kills on its very next cycle (streak=2 preserved).
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "7912"))
		if err := os.Chmod(stat7911, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(ctx, cycleEnv())
		if len(e.Kills) != 2 || e.Kills[1].PID != 7911 {
			t.Fatalf("kills=%+v want 7911 killed after recovery from preserved streak", e.Kills)
		}
	})
}

func TestR12MountinfoTaskRoot0000PreservesMarkerAndAborts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	id := strings.Repeat("f", 64)
	taskMount := filepath.Join(e.CtrDir, id, "rootfs")
	writeMountinfo(t, e, []string{miLine(taskMount)})
	marker := filepath.Join(e.StateDir, "mi-task-seen-"+id)
	wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-45*time.Minute).Unix()))

	if err := os.Chmod(e.CtrDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.CtrDir, 0o755) })

	e.SDReply["umount"] = ""
	miCycle(e)
	if e.SDRan("umount") {
		t.Fatalf("falsely unmounted task rootfs when CtrTaskRoot returned EACCES: cmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("mi-task-seen marker wiped under CtrTaskRoot EACCES: %v", err)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckMountinfo, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
}
