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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

func TestR12InotifySharedFDCachePoisonedSelfAndExternal(t *testing.T) {
	t.Run("self_poisoned_cache_within_TTL_still_arms_latch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		fdDir := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

		// Cycle 0 (t=0): SharedFDCache caches 0% omitting 4001; check aborts.
		inotifyRun(e, 1, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		// Permissions recover at t=5s -> Cycle 1 sets fails=1, Cycle 2 at t=10s (<60s) must arm!
		if err := os.Chmod(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(5 * time.Second)
		inotifyRun(e, 1, 4001)
		e.Now = e.Now.Add(5 * time.Second)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure failed to arm within 60s after Cycle 0 poisoned SharedFDCache")
		}
	})

	t.Run("external_hostmetrics_fdinfo_0000_within_TTL_detects_watches", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
		e.H.Cfg.Pressure.InotifyMaxWatchesCeiling = 100
		writeInotifySysctls(t, e, 100, 100)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 1, 98, "")

		// hostmetrics populates SharedFDCache while fdinfo/1 is 0o000 -> caches Watches=0.
		fdinfo1 := filepath.Join(e.ProcDir, "4001", "fdinfo", "1")
		if err := os.Chmod(fdinfo1, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdinfo1, 0o644) })
		_ = procfs.SharedFDCache(e.ProcDir, func() time.Time { return e.Now }).Snapshot(60 * time.Second)

		// fdinfo/1 recovers <60s later -> Cycle 1 & Cycle 2 must read live 98 watches and arm!
		if err := os.Chmod(fdinfo1, 0o644); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(5 * time.Second)
		inotifyRun(e, 1, 4001)
		e.Now = e.Now.Add(5 * time.Second)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure failed to arm when hostmetrics cached Watches=0 during fdinfo 0o000")
		}
	})
}

func TestR12CSIGuardAPIOKFalsePreservesLatchAndState(t *testing.T) {
	cn := csiNode("node-a", "csi.bad.com", "csi.ok.com")
	badPod := csiPluginPod("csi-bad-node-a", "kube-system", "uid-bad")
	badPod.Spec.Volumes = []corev1.Volume{{
		Name: "plugin-dir",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/k0s/kubelet/plugins/csi.bad.com"},
		},
	}}
	e := fixture(t, cn, badPod)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = false
	e.H.Cfg.Wave2.CSIGuardMissingMin = 0
	mkRegSocket(t, e, "csi.ok.com")

	chk := e.H.Check(wdeps.CheckCSIGuard)
	for range 3 {
		chk.Run(context.Background(), cycleWithPods(*badPod))
	}
	if !latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("setup: LatchCSIRegistrationWedged not armed")
	}

	// API blip (!APIOK) -> must abort and preserve LatchCSIRegistrationWedged.
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: false})
	if !latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("LatchCSIRegistrationWedged falsely exited on !e.APIOK")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCSIGuard, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}

	// Recovery with socket present clears cleanly.
	mkRegSocket(t, e, "csi.bad.com")
	chk.Run(context.Background(), cycleWithPods(*badPod))
	if latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("LatchCSIRegistrationWedged did not exit after recovery")
	}
}

func TestR12GPUGuardAPIOKFalseAndLiveGPUsEACCES(t *testing.T) {
	t.Run("APIOK_false_preserves_desyncSince_for_unready_plugin", func(t *testing.T) {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Status: corev1.NodeStatus{
				Capacity:    corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")},
				Allocatable: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")},
			},
		}
		plugin := gpuPluginPod("nvidia-device-plugin-x", "gpu-operator", "uid-gpu")
		plugin.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionFalse,
		}}
		e := gpuEnv(t, node, plugin)
		root := filepath.Dir(e.KubepodsDir)
		mkSysfsGPU(t, filepath.Join(root, "sys"), "0000:01:00.0")
		e.H.Cfg.Wave2.GPUGuardMode = envx.ModeOn
		e.H.Cfg.Wave2.GPUHealEnabled = true
		e.H.Cfg.Wave2.GPUGuardDesyncMin = 5

		chk := e.H.Check(wdeps.CheckGPUGuard)
		// t=0: arms desyncSince.
		chk.Run(context.Background(), cycleWithPods(*plugin))
		// t=4m: transient !APIOK -> must abort and preserve desyncSince.
		e.Now = e.Now.Add(4 * time.Minute)
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: false})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckGPUGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		// t=6m (>5m): API recovers -> must bounce plugin pod now.
		e.Now = e.Now.Add(2 * time.Minute)
		chk.Run(context.Background(), cycleWithPods(*plugin))
		_, err := e.CS.CoreV1().Pods("gpu-operator").Get(context.Background(), "nvidia-device-plugin-x", metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("expected plugin pod bounced at t=6m after !APIOK blip, get err=%v", err)
		}
	})

	t.Run("sysfs_vendor_0000_aborts_without_wiping_desyncSince", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
		plugin := gpuPluginPod("nvidia-device-plugin-x", "gpu-operator", "uid-gpu")
		e := gpuEnv(t, node, plugin)
		root := filepath.Dir(e.KubepodsDir)
		mkSysfsGPU(t, filepath.Join(root, "sys"), "0000:01:00.0")
		e.H.Cfg.Wave2.GPUGuardMode = envx.ModeOn
		e.H.Cfg.Wave2.GPUHealEnabled = true
		e.H.Cfg.Wave2.GPUGuardDesyncMin = 5

		chk := e.H.Check(wdeps.CheckGPUGuard)
		chk.Run(context.Background(), cycleWithPods(*plugin)) // t=0 arms desyncSince

		vendorPath := filepath.Join(root, "sys", "devices", "pci0000:00", "0000:01:00.0", "vendor")
		if err := os.Chmod(vendorPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(vendorPath, 0o644) })

		e.Now = e.Now.Add(4 * time.Minute)
		chk.Run(context.Background(), cycleWithPods(*plugin)) // vendor EACCES -> abort
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckGPUGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		if err := os.Chmod(vendorPath, 0o644); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(2 * time.Minute)
		chk.Run(context.Background(), cycleWithPods(*plugin)) // t=6m bounces from preserved desyncSince
		_, err := e.CS.CoreV1().Pods("gpu-operator").Get(context.Background(), "nvidia-device-plugin-x", metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("expected plugin pod bounced at t=6m after sysfs vendor recovery, get err=%v", err)
		}
	})
}

func TestR12SubprocOOMPartialCgroupProcs0000(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "subproc-pod", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	scopeDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice",
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice",
		"cri-containerd-app.scope")
	evPath := filepath.Join(scopeDir, "memory.events")
	procsPath := filepath.Join(scopeDir, "cgroup.procs")
	wdepstest.WriteFile(t, evPath, "oom_kill 1\noom_group_kill 0\n")
	wdepstest.WriteFile(t, procsPath, "1234\n")

	chk := e.H.Check(wdeps.CheckSubprocOOM)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), ce) // baseline at t=0

	// oom_kill increments at t=10s while cgroup.procs is 0o000.
	if err := os.Chmod(procsPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(procsPath, 0o644) })
	wdepstest.WriteFile(t, evPath, "oom_kill 2\noom_group_kill 0\n")
	e.Now = e.Now.Add(10 * time.Second)
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSubprocOOM, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}

	// Recover at t=80s (+70s) with same pid1=1234 -> must emit ContainerSubprocessOOMKilled.
	if err := os.Chmod(procsPath, 0o644); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(70 * time.Second)
	chk.Run(context.Background(), ce)
	if e.H.ContainerSubprocessOOM != 1 {
		t.Fatalf("ContainerSubprocessOOM=%d want 1", e.H.ContainerSubprocessOOM)
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerSubprocessOOMKilled" {
		t.Fatalf("events=%+v err=%v", evs.Items, err)
	}

	// Genuine restart (pid1 changes to 5678 after recovery) does not false-emit.
	wdepstest.WriteFile(t, evPath, "oom_kill 3\noom_group_kill 0\n")
	if err := os.Chmod(procsPath, 0o000); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(10 * time.Second)
	chk.Run(context.Background(), ce)
	if err := os.Chmod(procsPath, 0o644); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, procsPath, "5678\n")
	e.Now = e.Now.Add(70 * time.Second)
	chk.Run(context.Background(), ce)
	if e.H.ContainerSubprocessOOM != 1 {
		t.Fatalf("ContainerSubprocessOOM=%d want 1 (genuine restart should not emit)", e.H.ContainerSubprocessOOM)
	}
}

func TestR12KernelNetShimStatAndComm0000PreservesLatchAndGauges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "1", "net", "netstat"), "TcpExt: ListenDrops ListenOverflows\nTcpExt: 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "net", "softnet_stat"), "00000001 00000000 00000000\n")

	pdir := filepath.Join(e.ProcDir, "7001")
	statPath := filepath.Join(pdir, "stat")
	commPath := filepath.Join(pdir, "comm")
	statusPath := filepath.Join(pdir, "status")
	wdepstest.WriteFile(t, statPath, "7001 (containerd-shim) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
	wdepstest.WriteFile(t, commPath, "containerd-shim\n")
	wdepstest.WriteFile(t, filepath.Join(pdir, "cmdline"), "containerd-shim-runc-v2\x00-id\x00abc\x00")
	wdepstest.WriteFile(t, statusPath, fmt.Sprintf("VmRSS:\t%d kB\n", 300*1024))

	chk := e.H.Check(wdeps.CheckKernelNetShim)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{1, 7001} },
		PidsOK:       func() bool { return true },
	}
	chk.Run(context.Background(), ce)
	if !latched(e, latchdefs.LatchKernelNetShim) {
		t.Fatal("setup: LatchKernelNetShim not armed")
	}
	wantRSS := int64(300) << 20
	if e.H.ContainerdShimMaxRSSBytes != wantRSS {
		t.Fatalf("setup maxRSS=%d want %d", e.H.ContainerdShimMaxRSSBytes, wantRSS)
	}

	if err := os.Chmod(statPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(commPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(statPath, 0o644)
		_ = os.Chmod(commPath, 0o644)
	})

	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !latched(e, latchdefs.LatchKernelNetShim) {
		t.Fatal("LatchKernelNetShim exited on /proc/7001/{stat,comm} 0o000")
	}
	if e.H.ContainerdShimMaxRSSBytes != wantRSS {
		t.Fatalf("ContainerdShimMaxRSSBytes clobbered=%d want %d", e.H.ContainerdShimMaxRSSBytes, wantRSS)
	}

	// Restore and drop RSS -> exits cleanly.
	_ = os.Chmod(statPath, 0o644)
	_ = os.Chmod(commPath, 0o644)
	wdepstest.WriteFile(t, statusPath, "VmRSS:\t10240 kB\n")
	chk.Run(context.Background(), ce)
	if latched(e, latchdefs.LatchKernelNetShim) {
		t.Fatal("LatchKernelNetShim did not exit after recovery")
	}
}

func TestR12WritableLayerSnapshots0000DoesNotBurnCooldown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.DiskUsed = 0.90
	e.H.Cfg.Disk.BloatScanInterval = 15 * time.Minute
	e.H.Cfg.Disk.WLayerBloatThresholdBytes = 100
	snaps := filepath.Join(e.H.Cfg.K0sDataDir, "containerd", "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	e.H.Cfg.Disk.WLayerSnapshotsDir = snaps
	wdepstest.WriteFile(t, filepath.Join(snaps, "99", "fs", "blob"), strings.Repeat("x", 500))

	if err := os.Chmod(snaps, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(snaps, 0o755) })

	chk := e.H.Check(wdeps.CheckWritableLayer)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckWritableLayer, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-wlayer-scan")); !os.IsNotExist(err) {
		t.Fatalf("last-wlayer-scan cooldown burned on unreadable WLayerSnapshotsDir: err=%v", err)
	}

	// Recover < BloatScanInterval (+1m < 15m) -> detects bloated snapshot immediately!
	if err := os.Chmod(snaps, 0o755); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(time.Minute)
	chk.Run(context.Background(), ce)
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerWritableLayerBloat" {
		t.Fatalf("expected ContainerWritableLayerBloat after recovery <15m, events=%+v err=%v", evs.Items, err)
	}
}
