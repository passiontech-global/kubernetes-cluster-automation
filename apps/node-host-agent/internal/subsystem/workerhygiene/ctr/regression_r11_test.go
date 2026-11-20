package ctr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR11CtrMetaInitPidEACCESDoesNotFalseLatchAndAborts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	id := strings.Repeat("a", 64)
	orphanShim(t, e, 9001, id, "/run/k0s/containerd.sock", 20*time.Minute)
	taskDir := filepath.Join(filepath.Dir(e.CtrDir), "k8s.io", id)
	initPidPath := filepath.Join(taskDir, "init.pid")
	e.MkProc(t, 9002, "S", "", "")
	e.Live[9002] = true
	wdepstest.WriteFile(t, initPidPath, "9002\n")
	old := e.Now.Add(-20 * time.Minute)
	if err := os.Chtimes(taskDir, old, old); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(initPidPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(initPidPath, 0o644) })

	chk := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{9001, 9002} },
		PidsOK:       func() bool { return true },
		JournalOnce:  func() string { return "" },
		JournalOK:    func() bool { return true },
	}
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt falsely armed when init.pid returned EACCES")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2", got)
	}

	// Pre-arm latch and ensure EACCES on init.pid preserves it, then recovery clears it.
	e.H.State.Enter(latchdefs.LatchContainerdCorrupt, "prior")
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt cleared on init.pid EACCES")
	}

	if err := os.Chmod(initPidPath, 0o644); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt did not exit when live init.pid became readable")
	}

	// Intentional ENOENT on init.pid (>15m reparented shim) still counts as orphan evidence.
	if err := os.Remove(initPidPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(taskDir, old, old); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt did not arm on genuinely missing (ENOENT) init.pid")
	}
}

func TestR11CtrTasksUnreadableFilesPreserveLiveTasksAndMarkers(t *testing.T) {
	t.Run("sandbox_config_json_0000_no_kill_or_rm", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		id := "0a0d0b00" + strings.Repeat("c", 56)
		taskDir := filepath.Join(e.CtrDir, id)
		e.MkProc(t, 9101, "S", "pause", "")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9101", "cgroup"),
			"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/pause.scope\n")
		e.Live[9101] = true
		wdepstest.WriteFile(t, filepath.Join(taskDir, "init.pid"), "9101\n")
		cfgPath := filepath.Join(taskDir, "config.json")
		wdepstest.WriteFile(t, cfgPath, `{"annotations":{"io.kubernetes.cri.container-type":"sandbox"}}`)
		// Pre-seed aged wedged marker (>5m) to test worst-case kill path.
		marker := filepath.Join(e.StateDir, "wedged-seen-"+id)
		wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))

		if err := os.Chmod(cfgPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o644) })

		e.H.Check(wdeps.CheckCtrTasks).Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{9101} },
			PidsOK:       func() bool { return true },
		})
		if len(e.Kills) != 0 {
			t.Fatalf("falsely killed pause init on config.json EACCES: %+v", e.Kills)
		}
		if _, err := os.Stat(taskDir); err != nil {
			t.Fatalf("falsely removed sandbox task dir on config.json EACCES: %v", err)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("marker wiped on config.json EACCES: %v", err)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})

	t.Run("container_init_pid_and_log_json_0000_no_kill_and_enoent_cleans", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		id := "deadc0de" + strings.Repeat("a", 56)
		taskDir := filepath.Join(e.CtrDir, id)
		e.MkStatProc(t, 9106, "containerd-shim", "S", "")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9106", "cmdline"),
			"containerd-shim-runc-v2\x00-id\x00"+id+"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00")
		e.MkProc(t, 9107, "S", "app", "")
		e.Live[9107] = true
		initPath := filepath.Join(taskDir, "init.pid")
		logPath := filepath.Join(taskDir, "log.json")
		wdepstest.WriteFile(t, initPath, "9107\n")
		wdepstest.WriteFile(t, filepath.Join(taskDir, "config.json"), `{"annotations":{}}`)
		wdepstest.WriteFile(t, logPath, "{}\n")
		marker := filepath.Join(e.StateDir, "wedged-seen-"+id)
		wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))

		// Case A: init.pid 0o000 -> no kill, no rm, marker preserved, abort=1.
		if err := os.Chmod(initPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(initPath, 0o644) })

		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{9106, 9107} },
			PidsOK:       func() bool { return true },
		}
		chk := e.H.Check(wdeps.CheckCtrTasks)
		chk.Run(context.Background(), ce)
		if len(e.Kills) != 0 {
			t.Fatalf("falsely killed shim on init.pid EACCES: %+v", e.Kills)
		}
		if _, err := os.Stat(taskDir); err != nil {
			t.Fatalf("falsely removed task dir on init.pid EACCES: %v", err)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("marker wiped on init.pid EACCES: %v", err)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		// Case B: restore init.pid, replace log.json with ELOOP symlink -> os.Stat fails non-ENOENT -> no kill, no rm, marker preserved, abort=2.
		if err := os.Chmod(initPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(logPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(logPath, logPath); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce)
		if len(e.Kills) != 0 {
			t.Fatalf("falsely killed on log.json ELOOP: %+v", e.Kills)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("marker wiped on log.json ELOOP: %v", err)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 2 {
			t.Fatalf("abort=%v want 2", got)
		}

		// Case C: intentional ENOENT on init.pid (>5m) cleans up cleanly!
		if err := os.Remove(logPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(initPath); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce)
		if len(e.Kills) != 1 || e.Kills[0].PID != 9106 {
			t.Fatalf("kills=%+v want shim 9106 killed on ENOENT init.pid >5m", e.Kills)
		}
		if _, err := os.Stat(taskDir); !os.IsNotExist(err) {
			t.Fatalf("wedged task dir not removed on ENOENT init.pid >5m: err=%v", err)
		}
	})
}

func TestR11CtrTasksDZShimFdAndSShimCmdlineEACCES(t *testing.T) {
	t.Run("dz_shim_fd_0000_preserves_pod_teardown_wedged", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		sid := strings.Repeat("d", 64)
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9400", "stat"),
			"9400 (containerd-shim) D 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		fdDir := filepath.Join(e.ProcDir, "9400", "fd")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(e.CtrDir, sid, "log.json (deleted)"), filepath.Join(fdDir, "3")); err != nil {
			t.Fatal(err)
		}
		old := e.Now.Add(-10 * time.Minute)
		if err := os.Chtimes(filepath.Join(e.ProcDir, "9400"), old, old); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckCtrTasks)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{9400} },
			PidsOK:       func() bool { return true },
		}
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("setup: LatchPodTeardownWedged not armed")
		}

		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("LatchPodTeardownWedged falsely exited when /proc/9400/fd returned EACCES")
		}

		// Recovery: shim exits (ENOENT) -> releases CtrTasks hold cleanly.
		_ = os.Chmod(fdDir, 0o755)
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "9400"))
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("LatchPodTeardownWedged did not exit after D-state shim exited")
		}
	})

	t.Run("s_shim_cmdline_0000_preserves_sandbox_ctl_dir", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		sid := strings.Repeat("c", 64)
		sbDir := filepath.Join(e.H.Cfg.SandboxCtlRoot, sid)
		if err := os.MkdirAll(sbDir, 0o755); err != nil {
			t.Fatal(err)
		}
		old := e.Now.Add(-45 * time.Minute)
		if err := os.Chtimes(sbDir, old, old); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.StateDir, "sandbox-orphan-seen-"+sid),
			strconv.FormatInt(e.Now.Add(-40*time.Minute).Unix(), 10)+"\n")

		// S-state shim holding this sandbox id, with /proc/9500/cmdline 0o000.
		e.MkStatProc(t, 9500, "containerd-shim", "S", "")
		cmdPath := filepath.Join(e.ProcDir, "9500", "cmdline")
		wdepstest.WriteFile(t, cmdPath,
			"containerd-shim-runc-v2\x00-id\x00"+sid+"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00")
		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })

		e.H.Check(wdeps.CheckCtrTasks).Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{9500} },
			PidsOK:       func() bool { return true },
		})
		if _, err := os.Stat(sbDir); err != nil {
			t.Fatalf("cri-sandbox-reaper falsely removed live SandboxCtlRoot/%s when shim cmdline returned EACCES: %v", sid, err)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}

func TestR11HungRuncCmdlineAndStatEACCES(t *testing.T) {
	t.Run("cmdline_0000_does_not_kill_runc_exec", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := hungEnv(t, 1)
		e.MkStatProc(t, 7901, "runc", "S", "futex_wait")
		cmdPath := filepath.Join(e.ProcDir, "7901", "cmdline")
		wdepstest.WriteFile(t, cmdPath, "runc\x00exec\x00cid\x00sh\x00")
		ageProc(t, e, 7901, 10*time.Minute)
		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })

		hungCheck(e).Run(context.Background(), cycleEnv())
		if len(e.Kills) != 0 {
			t.Fatalf("SIGKILLed runc exec when cmdline returned EACCES: %+v", e.Kills)
		}
	})

	t.Run("stat_0000_aborts_and_preserves_streak", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := hungEnv(t, 2)
		e.MkStatProc(t, 7902, "runc", "S", "do_wait")
		ageProc(t, e, 7902, 10*time.Minute)
		chk := hungCheck(e)
		ctx := context.Background()

		chk.Run(ctx, cycleEnv()) // streak=1
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected kill on cycle 1: %+v", e.Kills)
		}
		statPath := filepath.Join(e.ProcDir, "7902", "stat")
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		chk.Run(ctx, cycleEnv()) // abort, preserves streak=1
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckHungRunc, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		if err := os.Chmod(statPath, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(ctx, cycleEnv()) // streak=2 -> kills
		if len(e.Kills) != 1 || e.Kills[0].PID != 7902 {
			t.Fatalf("kills=%+v want SIGKILL on 7902 from preserved streak", e.Kills)
		}
	})
}
