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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR10InotifyMultiPIDPartialFDAndFDInfoUnreadableAbortsPreservesLatch(t *testing.T) {
	t.Run("pid1_readable_pid4001_fd_0000_and_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		inotifyRun(e, 1, 4001)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}

		fdDir := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 1, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited when /proc/1/fd was readable and /proc/4001/fd was 0o000")
		}

		// Recovery: restore permissions and clear inotify fds -> exits cleanly.
		if err := os.Chmod(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		mkInotifyPID(t, e, 4001, 0, 0, "")
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 1, 4001)
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit after recovery")
		}
	})

	t.Run("fdinfo_0000_under_watch_pressure_and_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 8192
		e.H.Cfg.Pressure.InotifyMaxWatchesCeiling = 100
		writeInotifySysctls(t, e, 8192, 100)
		mkInotifyPID(t, e, 4001, 1, 100, "")
		inotifyRun(e, 4001)
		inotifyRun(e, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed on watch pressure")
		}

		fdinfoFile := filepath.Join(e.ProcDir, "4001", "fdinfo", "1")
		if err := os.Chmod(fdinfoFile, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdinfoFile, 0o644) })

		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited when /proc/4001/fdinfo/1 returned 0o000")
		}

		// Recovery: restore permissions with 0 watches -> exits cleanly.
		if err := os.Chmod(fdinfoFile, 0o644); err != nil {
			t.Fatal(err)
		}
		mkInotifyPID(t, e, 4001, 1, 0, "")
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 4001)
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit after watch recovery")
		}
	})
}

func TestR10KernelNetShimShimStatusUnreadablePreservesLatchAndGauges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	mkShim(t, e, 5000, 250*1024, "task-shim-leak")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchKernelNetShim) {
		t.Fatal("setup: LatchKernelNetShim not armed")
	}
	wantBytes := int64(250 * 1024 << 10)
	if e.H.Series.ContainerdShimMaxRSSBytes != wantBytes || e.H.Series.ContainerdShimTotalRSSBytes != wantBytes {
		t.Fatalf("setup gauges=%d/%d want %d", e.H.Series.ContainerdShimMaxRSSBytes, e.H.Series.ContainerdShimTotalRSSBytes, wantBytes)
	}

	statusPath := filepath.Join(e.ProcDir, "5000", "status")
	if err := os.Chmod(statusPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(statusPath, 0o644) })

	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchKernelNetShim) {
		t.Fatal("LatchKernelNetShim falsely exited when /proc/5000/status returned 0o000")
	}
	if e.H.Series.ContainerdShimMaxRSSBytes != wantBytes || e.H.Series.ContainerdShimTotalRSSBytes != wantBytes {
		t.Fatalf("shim RSS gauges clobbered: max=%d total=%d want %d",
			e.H.Series.ContainerdShimMaxRSSBytes, e.H.Series.ContainerdShimTotalRSSBytes, wantBytes)
	}

	// Recovery: restore status with healthy 20MiB RSS -> exits latch and updates gauges.
	if err := os.Chmod(statusPath, 0o644); err != nil {
		t.Fatal(err)
	}
	mkShim(t, e, 5000, 20*1024, "task-shim-leak")
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchKernelNetShim) {
		t.Fatal("LatchKernelNetShim did not exit after shim RSS recovery")
	}
	if e.H.Series.ContainerdShimMaxRSSBytes != 20*1024<<10 {
		t.Fatalf("recovered max RSS=%d want %d", e.H.Series.ContainerdShimMaxRSSBytes, 20*1024<<10)
	}
}

func TestR10CgroupThrottlePodSliceUnreadablePreservesRatio(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	cg := t.TempDir()
	e.H.Cfg.Runtime.CgroupRoot = cg
	podSliceRel := filepath.Join("kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	podSlice := filepath.Join(cg, podSliceRel)
	mkPodSlice(t, cg, podSliceRel, "1.00", "0", "90", "100", "0")

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), ce)
	if e.H.PodCgroupPIDsMaxUtilRatio != 0.9 {
		t.Fatalf("setup ratio=%v want 0.9", e.H.PodCgroupPIDsMaxUtilRatio)
	}

	// chmod 0o000 pod slice dir -> must abort and preserve PodCgroupPIDsMaxUtilRatio=0.9.
	if err := os.Chmod(podSlice, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(podSlice, 0o755) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if e.H.PodCgroupPIDsMaxUtilRatio != 0.9 {
		t.Fatalf("PodCgroupPIDsMaxUtilRatio clobbered=%v want 0.9", e.H.PodCgroupPIDsMaxUtilRatio)
	}

	// Restore permissions with lower usage -> ratio updates cleanly.
	if err := os.Chmod(podSlice, 0o755); err != nil {
		t.Fatal(err)
	}
	mkPodSlice(t, cg, podSliceRel, "1.00", "0", "10", "100", "0")
	chk.Run(context.Background(), ce)
	if e.H.PodCgroupPIDsMaxUtilRatio != 0.1 {
		t.Fatalf("recovered ratio=%v want 0.1", e.H.PodCgroupPIDsMaxUtilRatio)
	}
}

func TestR10CgroupThrottleCPUStatUnreadablePreservesCPUEvented(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cfs-pod", UID: types.UID(wdepstest.UIDB)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	sliceDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDB, "-", "_")+".slice")
	if err := os.MkdirAll(sliceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.pressure"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), "high 0\n")
	cpuStatPath := filepath.Join(sliceDir, "cpu.stat")
	procStatPath := filepath.Join(e.ProcDir, "stat")
	wdepstest.WriteFile(t, procStatPath, "cpu  0 0 0 0 0 0 0 0\n")
	wdepstest.WriteFile(t, cpuStatPath, "nr_periods 100\nnr_throttled 0\n")

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), ce) // baseline
	for i := 1; i <= 3; i++ {
		wdepstest.WriteFile(t, procStatPath, fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, cpuStatPath, fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "PodCPUCFSThrottled" {
		t.Fatalf("setup events=%+v err=%v", evs.Items, err)
	}

	// chmod 0o000 cpu.stat -> must abort and NOT delete cpuEvented[dir].
	if err := os.Chmod(cpuStatPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cpuStatPath, 0o644) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}

	// Restore cpu.stat still throttling (continuing episode) -> must NOT emit duplicate Event.
	if err := os.Chmod(cpuStatPath, 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 4; i <= 6; i++ {
		wdepstest.WriteFile(t, procStatPath, fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, cpuStatPath, fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
	}
	evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 {
		t.Fatalf("events=%d want 1 (cpuEvented was cleared during cpu.stat 0o000)", len(evs.Items))
	}
}

func TestR10VMAPressureMapsUnreadablePreservesRatio(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.H.Cfg.Wave3.VMAMaxCeiling = 100
	if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	sysVM := filepath.Join(e.ProcDir, "sys", "vm")
	if err := os.MkdirAll(sysVM, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysVM, "max_map_count"), "100\n")

	pidDir := filepath.Join(e.ProcDir, "5001")
	wdepstest.WriteFile(t, filepath.Join(pidDir, "stat"),
		"5001 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 "+fmt.Sprintf("%d", 1<<30)+" 0\n")
	var mapsBuf strings.Builder
	for i := range 90 {
		fmt.Fprintf(&mapsBuf, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
	}
	mapsPath := filepath.Join(pidDir, "maps")
	wdepstest.WriteFile(t, mapsPath, mapsBuf.String())

	e.H.Cycle(context.Background())
	if e.H.Series.VMAMaxUtilRatio != 0.9 {
		t.Fatalf("setup VMAMaxUtilRatio=%v want 0.9", e.H.Series.VMAMaxUtilRatio)
	}

	if err := os.Chmod(mapsPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mapsPath, 0o644) })
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if e.H.Series.VMAMaxUtilRatio != 0.9 {
		t.Fatalf("VMAMaxUtilRatio clobbered=%v want 0.9", e.H.Series.VMAMaxUtilRatio)
	}

	// Restore permissions with 10 mappings -> updates ratio cleanly.
	if err := os.Chmod(mapsPath, 0o644); err != nil {
		t.Fatal(err)
	}
	mapsBuf.Reset()
	for i := range 10 {
		fmt.Fprintf(&mapsBuf, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
	}
	wdepstest.WriteFile(t, mapsPath, mapsBuf.String())
	e.H.Cycle(context.Background())
	if e.H.Series.VMAMaxUtilRatio != 0.1 {
		t.Fatalf("recovered VMAMaxUtilRatio=%v want 0.1", e.H.Series.VMAMaxUtilRatio)
	}
}

func TestR10EphemeralPortsProcUnreadablePreservesPortLeakMarkers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	isCtrl := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "leaker", UID: types.UID(wdepstest.UIDA),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-1", Controller: &isCtrl,
		}},
	}}
	e := fixture(t, pod)
	e.H.Cfg.Wave2.PortEvictRunawayPod = true
	e.H.Cfg.Wave2.PortLeakMinPct = 50
	e.H.Cfg.Wave2.PortLeakWindowSec = 120
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "net", "ipv4", "ip_local_port_range"), "32768 33767\n")

	var tcpBuf strings.Builder
	tcpBuf.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	fdDir := filepath.Join(e.ProcDir, "200", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 1200 {
		inode := 90000 + i
		fmt.Fprintf(&tcpBuf, "%4d: 0100007F:1F90 0100007F:C350 08 00000000:00000000 00:00000000 00000000 0 0 %d 1 00000000 0\n", i, inode)
		if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fdDir, fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	tcpPath := filepath.Join(e.ProcDir, "1", "net", "tcp")
	wdepstest.WriteFile(t, tcpPath, tcpBuf.String())
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "200", "cgroup"),
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+
			strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-abc.scope\n")
	nsDir := filepath.Join(e.ProcDir, "1", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("net:[1001]", filepath.Join(nsDir, "net"))

	e.H.Cfg.Seams.Host.TCPTablesFn = func(int) (netlinkx.TCPCensus, error) {
		return netlinkx.TCPCensus{States: map[uint8]int{8: 1200}}, nil
	}
	chk := e.H.Check(wdeps.CheckEphemeralPorts)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*pod},
		PidsOnce:     func() []int { return []int{1, 200} },
		PidsOK:       func() bool { return true },
	}

	// Cycle 1: stamps port-leak-<uid> marker.
	chk.Run(context.Background(), ce)
	markerPath := filepath.Join(e.StateDir, "port-leak-"+wdepstest.UIDA)
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("setup marker missing: %v", err)
	}

	// Cycle 2 at t+60s: /proc/1/net/tcp 0o000 -> must abort and preserve port-leak-<uid>.
	e.Now = e.Now.Add(60 * time.Second)
	if err := os.Chmod(tcpPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tcpPath, 0o644) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckEphemeralPorts, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("port-leak marker wiped when /proc/1/net/tcp returned 0o000: %v", err)
	}

	// Restore /proc/1/net/tcp, make /proc/200/fd 0o000 -> still preserves port-leak-<uid>.
	if err := os.Chmod(tcpPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fdDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckEphemeralPorts, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2", got)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("port-leak marker wiped when /proc/200/fd returned 0o000: %v", err)
	}

	// Restore /proc/200/fd at t+130s -> preserved confirm window fires eviction cleanly!
	if err := os.Chmod(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(70 * time.Second)
	chk.Run(context.Background(), ce)
	if dels := wdepstest.DeleteActions(e.CS); len(dels) != 1 || dels[0].GetName() != "leaker" {
		t.Fatalf("deletes=%+v want 1 delete of leaker after preserved window", dels)
	}
}
