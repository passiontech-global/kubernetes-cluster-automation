package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestSystemdSessionUnreadableDirAbortsPreservesLatchAndGauges(t *testing.T) {
	setupArmed := func(t *testing.T) (*env, string) {
		t.Helper()
		e := fixture(t)
		sessDir := t.TempDir()
		e.H.Cfg.Runtime.SessionsDir = sessDir
		stale := e.Now.Add(-3 * time.Hour)
		for i := range 20 {
			p := filepath.Join(sessDir, fmt.Sprintf("s%d", i))
			wdepstest.WriteFile(t, p, "STATE=abandoned\n")
			if err := os.Chtimes(p, stale, stale); err != nil {
				t.Fatal(err)
			}
		}
		chk := wdepstest.Check[*runtime.SystemdSessionCheck](e.H, wdeps.CheckSystemdSessions)
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
		if !e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
			t.Fatal("setup: LatchSystemdSessionBloat not armed")
		}
		if e.H.SystemdSessionsTotal != 20 || e.H.SystemdSessionsStale != 20 {
			t.Fatalf("setup gauges=%d/%d want 20/20", e.H.SystemdSessionsTotal, e.H.SystemdSessionsStale)
		}
		return e, sessDir
	}

	t.Run("EACCES_0000_and_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, sessDir := setupArmed(t)
		if err := os.Chmod(sessDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(sessDir, 0o755) })

		chk := wdepstest.Check[*runtime.SystemdSessionCheck](e.H, wdeps.CheckSystemdSessions)
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
			t.Fatal("LatchSystemdSessionBloat falsely exited on SessionsDir 0o000")
		}
		if e.H.SystemdSessionsTotal != 20 || e.H.SystemdSessionsStale != 20 {
			t.Fatalf("gauges clobbered=%d/%d want 20/20", e.H.SystemdSessionsTotal, e.H.SystemdSessionsStale)
		}

		// Recovery: chmod 0755 and mark sessions active -> exits cleanly.
		if err := os.Chmod(sessDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := range 20 {
			wdepstest.WriteFile(t, filepath.Join(sessDir, fmt.Sprintf("s%d", i)), "STATE=active\n")
		}
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
		if e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
			t.Fatal("LatchSystemdSessionBloat did not exit after recovery")
		}
	})

	t.Run("ENOTDIR_preserves_and_ENOENT_dormant", func(t *testing.T) {
		e, sessDir := setupArmed(t)
		if err := os.RemoveAll(sessDir); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, sessDir, "not a dir\n")
		chk := wdepstest.Check[*runtime.SystemdSessionCheck](e.H, wdeps.CheckSystemdSessions)
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
		if !e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
			t.Fatal("LatchSystemdSessionBloat falsely exited on SessionsDir ENOTDIR")
		}

		// ENOENT stays dormant/0 and exits ok.
		if err := os.Remove(sessDir); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
		if e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
			t.Fatal("expected ENOENT SessionsDir to be treated as dormant 0")
		}
		if e.H.SystemdSessionsTotal != 0 || e.H.SystemdSessionsStale != 0 {
			t.Fatalf("gauges=%d/%d want 0/0 on ENOENT", e.H.SystemdSessionsTotal, e.H.SystemdSessionsStale)
		}
	})
}

func TestInotifyProcFDUnreadableAbortsPreservesLatch(t *testing.T) {
	armInotify := func(t *testing.T, pid int) *env {
		t.Helper()
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, pid, 10, 1, "")
		inotifyRun(e, pid)
		inotifyRun(e, pid)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}
		return e
	}

	t.Run("EACCES_0000_and_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := armInotify(t, 4001)
		fdDir := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

		e.Now = e.Now.Add(65 * time.Second) // expire SharedFDCache TTL
		inotifyRun(e, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited on /proc/<pid>/fd 0o000")
		}

		// Recovery: readable fd dir with 0 inotify fds exits latch.
		if err := os.Chmod(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		mkInotifyPID(t, e, 4001, 0, 0, "")
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 4001)
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit on legitimate 0-inotify host")
		}
	})

	t.Run("ENOTDIR_preserves_latch", func(t *testing.T) {
		e := armInotify(t, 4002)
		fdDir := filepath.Join(e.ProcDir, "4002", "fd")
		if err := os.RemoveAll(fdDir); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, fdDir, "not a dir\n")
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 4002)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited on /proc/<pid>/fd ENOTDIR")
		}
	})
}

func TestCgroupThrottleAndSubprocOOMKubepodsUnreadablePreservesState(t *testing.T) {
	setupBoth := func(t *testing.T) (*env, string, string, *corev1.Pod) {
		t.Helper()
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		cg := t.TempDir()
		e.H.Cfg.Runtime.CgroupRoot = cg
		kubepods := filepath.Join(cg, "kubepods.slice")

		// Seed pids.max 90% utilization for CgroupThrottleCheck.
		slice := filepath.Join("kubepods.slice", "kubepods-burstable.slice",
			"kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
		mkPodSlice(t, cg, slice, "1.00", "0", "90", "100", "0")

		// Seed pending 60s confirm window for SubprocOOMCheck.
		scope := mkOOMScope(t, e, wdepstest.UIDA, "aaa111", 1, 4242)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		wdepstest.Check[*runtime.CgroupThrottleCheck](e.H, wdeps.CheckCgroupThrottle).Run(context.Background(), ce)
		if e.H.PodCgroupPIDsMaxUtilRatio != 0.9 {
			t.Fatalf("setup ratio=%v want 0.9", e.H.PodCgroupPIDsMaxUtilRatio)
		}
		subChk := wdepstest.Check[*runtime.SubprocOOMCheck](e.H, wdeps.CheckSubprocOOM)
		subChk.Run(context.Background(), ce) // baseline
		wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"), "oom_kill 2\n")
		subChk.Run(context.Background(), ce) // arms pendingAt
		return e, kubepods, scope, pod
	}

	t.Run("EACCES_0000_and_confirm_after_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, kubepods, _, pod := setupBoth(t)
		if err := os.Chmod(kubepods, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(kubepods, 0o755) })

		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		wdepstest.Check[*runtime.CgroupThrottleCheck](e.H, wdeps.CheckCgroupThrottle).Run(context.Background(), ce)
		wdepstest.Check[*runtime.SubprocOOMCheck](e.H, wdeps.CheckSubprocOOM).Run(context.Background(), ce)

		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
			t.Fatalf("cgroup abort=%v want 1", got)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSubprocOOM, "abort")); got != 1 {
			t.Fatalf("subproc-oom abort=%v want 1", got)
		}
		if e.H.PodCgroupPIDsMaxUtilRatio != 0.9 {
			t.Fatalf("PodCgroupPIDsMaxUtilRatio clobbered=%v want 0.9", e.H.PodCgroupPIDsMaxUtilRatio)
		}

		// Restore 0o755 + advance 65s -> pending SubprocOOMCheck window still fires!
		if err := os.Chmod(kubepods, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(65 * time.Second)
		wdepstest.Check[*runtime.SubprocOOMCheck](e.H, wdeps.CheckSubprocOOM).Run(context.Background(), ce)
		if e.H.ContainerSubprocessOOM != 1 {
			t.Fatalf("ContainerSubprocessOOM=%d want 1 (pending window lost across kubepods EACCES)", e.H.ContainerSubprocessOOM)
		}
	})

	t.Run("ENOTDIR_on_qos_slice_aborts", func(t *testing.T) {
		e, kubepods, _, pod := setupBoth(t)
		qos := filepath.Join(kubepods, "kubepods-burstable.slice")
		if err := os.RemoveAll(qos); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, qos, "not a dir\n")

		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		wdepstest.Check[*runtime.CgroupThrottleCheck](e.H, wdeps.CheckCgroupThrottle).Run(context.Background(), ce)
		wdepstest.Check[*runtime.SubprocOOMCheck](e.H, wdeps.CheckSubprocOOM).Run(context.Background(), ce)
		if e.H.PodCgroupPIDsMaxUtilRatio != 0.9 {
			t.Fatalf("PodCgroupPIDsMaxUtilRatio clobbered on QoS ENOTDIR: %v", e.H.PodCgroupPIDsMaxUtilRatio)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSubprocOOM, "abort")); got != 1 {
			t.Fatalf("subproc-oom abort=%v want 1", got)
		}
	})
}

func TestUnlinkedOpenFilesProcFDUnreadablePreservesGauges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.DiskUsed = 0.90
	e.MkStatProc(t, 4401, "app", "S", "")
	e.mkDeletedFD(t, 4401, 3, "/var/log/a.log")
	e.stubDeletedFDStats(map[string]deletedStat{"4401:3": {dev: 1, ino: 10, size: mib(128)}})

	chk := wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](e.H, wdeps.CheckUnlinkedOpenFiles)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if e.H.UnlinkedOpenFileBytes != mib(128) || e.H.UnlinkedOpenFileCount != 1 {
		t.Fatalf("setup gauges=%d/%d want %d/1", e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount, mib(128))
	}

	fdDir := filepath.Join(e.ProcDir, "4401", "fd")
	if err := os.Chmod(fdDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

	e.Now = e.Now.Add(e.H.Cfg.Disk.BloatScanInterval + time.Minute)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUnlinkedOpenFiles, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive=%v want 1", got)
	}
	if e.H.UnlinkedOpenFileBytes != mib(128) || e.H.UnlinkedOpenFileCount != 1 {
		t.Fatalf("gauges clobbered=%d/%d want %d/1", e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount, mib(128))
	}

	// Restore permissions without advancing clock -> immediate recovery runs.
	if err := os.Chmod(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if e.H.UnlinkedOpenFileBytes != 0 || e.H.UnlinkedOpenFileCount != 0 {
		t.Fatalf("recovered gauges=%d/%d want 0/0", e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount)
	}
}

func TestKernelNetShimNetstatUnreadableWhileSoftnetFlatPreservesLatch(t *testing.T) {
	armDropLatch := func(t *testing.T) (*env, string) {
		t.Helper()
		e := fixture(t)
		writeNetstat(t, e.ProcDir, 10, 0)
		writeSoftnet(t, e.ProcDir, "00000064 00000001 00000000 00000000 00000000")
		chk := e.H.Check(wdeps.CheckKernelNetShim)
		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		chk.Run(context.Background(), ce) // baseline
		writeNetstat(t, e.ProcDir, 20, 0)
		chk.Run(context.Background(), ce) // rise 1
		writeNetstat(t, e.ProcDir, 30, 0)
		chk.Run(context.Background(), ce) // rise 2 -> armed
		if !e.H.State.Exists(latchdefs.LatchKernelNetShim) {
			t.Fatal("setup: LatchKernelNetShim not armed")
		}
		return e, filepath.Join(e.ProcDir, "1", "net", "netstat")
	}

	t.Run("EACCES_0000_preserves_and_recovers", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, netstatPath := armDropLatch(t)
		if err := os.Chmod(netstatPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(netstatPath, 0o644) })

		chk := e.H.Check(wdeps.CheckKernelNetShim)
		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchKernelNetShim) {
			t.Fatal("LatchKernelNetShim falsely exited when netstat returned EACCES")
		}

		if err := os.Chmod(netstatPath, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce) // flat after recovery -> exits
		if e.H.State.Exists(latchdefs.LatchKernelNetShim) {
			t.Fatal("LatchKernelNetShim did not exit after flat recovery")
		}
	})

	t.Run("ENOENT_after_contributing_preserves_latch", func(t *testing.T) {
		e, netstatPath := armDropLatch(t)
		if err := os.Remove(netstatPath); err != nil {
			t.Fatal(err)
		}
		chk := e.H.Check(wdeps.CheckKernelNetShim)
		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchKernelNetShim) {
			t.Fatal("LatchKernelNetShim falsely exited when previously readable netstat vanished")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}

func TestDiskBloatNilClientDoesNotPanic(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Client = nil
	e.DiskUsed = e.H.Cfg.Disk.BloatCriticalWatermark + 0.05
	e.H.Cfg.Disk.BloatPodThresholdBytes = 1024
	uid := wdepstest.UIDA
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hog", Namespace: "default", UID: types.UID(uid),
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	vol := filepath.Join(e.KubepodsDir, uid, "volumes", "kubernetes.io~empty-dir", "data", "blob")
	wdepstest.WriteFile(t, vol, strings.Repeat("x", 4096))
	chk := wdepstest.Check[*runtime.DiskBloatCheck](e.H, wdeps.CheckDiskBloat)
	chk.Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{pod},
	})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-disk-bloat-evict")); !os.IsNotExist(err) {
		t.Fatal("last-disk-bloat-evict spent while Client==nil")
	}
}
