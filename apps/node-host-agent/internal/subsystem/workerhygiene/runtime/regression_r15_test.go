package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15KernelNetShimStat0000AndStaleStatsOnce(t *testing.T) {
	setupNet := func(t *testing.T, e *env) {
		t.Helper()
		writeNetstat(t, e.ProcDir, 10, 5)
		writeSoftnet(t, e.ProcDir, "00000064 00000000 00000000 00000000 00000000")
	}

	t.Run("stat_0000_readable_comm_fifo_cmdline_aborts_and_preserves_latch_and_gauges", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		setupNet(t, e)
		// Cycle 1: healthy oversized shim arms latch and sets RSS gauges.
		mkShim(t, e, 7200, 250*1024, "task-r15-1")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7200", "stat"),
			"7200 (containerd-shim) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		chk := e.H.Check(wdeps.CheckKernelNetShim)
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{7200} },
			PidsOK:       func() bool { return true },
		})
		latchPath := filepath.Join(e.StateDir, latchdefs.LatchFilePrefix+latchdefs.LatchKernelNetShim)
		if _, err := os.Stat(latchPath); err != nil {
			t.Fatalf("setup: latch not armed: %v", err)
		}
		if e.H.Series.ContainerdShimMaxRSSBytes != 250<<20 || e.H.Series.ContainerdShimTotalRSSBytes != 250<<20 {
			t.Fatalf("setup gauges=%d/%d", e.H.Series.ContainerdShimMaxRSSBytes, e.H.Series.ContainerdShimTotalRSSBytes)
		}

		// Replace cmdline with FIFO and chmod stat 0o000 while comm remains readable.
		cmdFIFO := filepath.Join(e.ProcDir, "7200", "cmdline")
		_ = os.Remove(cmdFIFO)
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		statPath := filepath.Join(e.ProcDir, "7200", "stat")
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		// Both StatsOnce==nil and StatsOnce omitting pid 7200 must abort without opening FIFO cmdline.
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{7200} },
				PidsOK:       func() bool { return true },
			})
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{7200} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return map[int]procfs.Stat{} },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "abort")); got != 2 {
			t.Fatalf("abort=%v want 2", got)
		}
		if _, err := os.Stat(latchPath); err != nil {
			t.Fatalf("LatchKernelNetShim cleared on abort: %v", err)
		}
		if e.H.Series.ContainerdShimMaxRSSBytes != 250<<20 || e.H.Series.ContainerdShimTotalRSSBytes != 250<<20 {
			t.Fatalf("RSS gauges clobbered on abort: %d/%d",
				e.H.Series.ContainerdShimMaxRSSBytes, e.H.Series.ContainerdShimTotalRSSBytes)
		}
	})

	t.Run("mkshim_enoent_stat_still_succeeds", func(t *testing.T) {
		e := fixture(t)
		setupNet(t, e)
		mkShim(t, e, 7201, 250*1024, "task-r15-enoent")
		chk := e.H.Check(wdeps.CheckKernelNetShim)
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{7201} },
			PidsOK:       func() bool { return true },
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
		if e.H.Series.ContainerdShimMaxRSSBytes != 250<<20 {
			t.Fatalf("maxRSS=%d want %d", e.H.Series.ContainerdShimMaxRSSBytes, 250<<20)
		}
	})

	t.Run("stale_statsonce_s_while_live_stat_0000_or_x_never_opens_fifo", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		setupNet(t, e)
		pdir := filepath.Join(e.ProcDir, "7202")
		wdepstest.WriteFile(t, filepath.Join(pdir, "comm"), "containerd-shim\n")
		wdepstest.WriteFile(t, filepath.Join(pdir, "status"), "VmRSS:\t1024 kB\n")
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath,
			"7202 (containerd-shim) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		staleSnap := map[int]procfs.Stat{
			7202: {Comm: "containerd-shim", HasComm: true, Fields: []string{"S", "1"}},
		}
		chk := e.H.Check(wdeps.CheckKernelNetShim)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{7202} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return staleSnap },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		// Live stat transitions to X -> completes ok without opening FIFO cmdline.
		if err := os.Chmod(statPath, 0o644); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, statPath,
			"7202 (containerd-shim) X 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{7202} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return staleSnap },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
	})
}

func TestR15VMAPressureStat0000AndMapsFIFOSafety(t *testing.T) {
	writeVMAProc := func(t *testing.T, e *env, pid int, state string, vsize int64, lines int, podUID string) (string, string) {
		t.Helper()
		pdir := filepath.Join(e.ProcDir, fmt.Sprint(pid))
		fields := make([]string, 21)
		fields[0] = state
		for i := 1; i < 20; i++ {
			fields[i] = "0"
		}
		fields[20] = fmt.Sprint(vsize)
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath, fmt.Sprintf("%d (java) %s\n", pid, strings.Join(fields, " ")))
		if podUID != "" {
			wdepstest.WriteFile(t, filepath.Join(pdir, "cgroup"),
				"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+
					strings.ReplaceAll(podUID, "-", "_")+".slice/cri-containerd-c1.scope\n")
		}
		var sb strings.Builder
		for i := range lines {
			fmt.Fprintf(&sb, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
		}
		mapsPath := filepath.Join(pdir, "maps")
		wdepstest.WriteFile(t, mapsPath, sb.String())
		return statPath, mapsPath
	}

	t.Run("full_cycle_stat_0000_aborts_preserves_ratio_and_vmaEvented", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vma-r15", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		e.H.Cfg.Wave3.VMAMaxCeiling = 100
		if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "max_map_count"), "100\n")

		stat5001, _ := writeVMAProc(t, e, 5001, "S", 1<<30, 90, wdepstest.UIDA)
		writeVMAProc(t, e, 5002, "S", 1<<20, 5, "")

		// Cycle 1 via real Hygiene.Cycle (uses statsOnce): ratio=0.90, emits 1 PodVMAMapCountPressure event.
		e.H.Cycle(context.Background())
		if e.H.Series.VMAMaxUtilRatio != 0.90 {
			t.Fatalf("setup VMAMaxUtilRatio=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
		}
		evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "PodVMAMapCountPressure" {
			t.Fatalf("setup events=%+v err=%v", evs.Items, err)
		}

		// chmod 0o000 /proc/5001/stat -> statsOnce omits 5001 while PidsOK() stays true.
		// Cycle MUST abort, preserve VMAMaxUtilRatio == 0.90, and preserve vmaEvented!
		if err := os.Chmod(stat5001, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(stat5001, 0o644) })
		prevAbort := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort"))
		e.H.Cycle(context.Background())
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != prevAbort+1 {
			t.Fatalf("abort=%v want %v", got, prevAbort+1)
		}
		if e.H.Series.VMAMaxUtilRatio != 0.90 {
			t.Fatalf("VMAMaxUtilRatio clobbered=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
		}

		// Also verify StatsOnce==nil path with stat 0o000 preserves ratio and aborts.
		chk := e.H.Check(wdeps.CheckCgroupThrottle)
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{*pod},
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != prevAbort+2 {
			t.Fatalf("StatsOnce==nil abort=%v want %v", got, prevAbort+2)
		}
		if e.H.Series.VMAMaxUtilRatio != 0.90 {
			t.Fatalf("StatsOnce==nil clobbered ratio=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
		}

		// Restore 0o644 -> no duplicate PodVMAMapCountPressure event!
		if err := os.Chmod(stat5001, 0o644); err != nil {
			t.Fatal(err)
		}
		e.H.Cycle(context.Background())
		evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 {
			t.Fatalf("events=%d want 1 (vmaEvented was wiped)", len(evs.Items))
		}
	})

	t.Run("candidate_restat_0000_with_fifo_maps_aborts_without_blocking", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Wave3.VMAMaxCeiling = 100
		if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "max_map_count"), "100\n")

		pdir := filepath.Join(e.ProcDir, "5003")
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath, "5003 (java) D 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 1073741824 0\n")
		mapsFIFO := filepath.Join(pdir, "maps")
		if err := unix.Mkfifo(mapsFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		fields := make([]string, 21)
		fields[0] = "S"
		fields[20] = "1073741824"
		staleSnap := map[int]procfs.Stat{
			5003: {Comm: "java", HasComm: true, Fields: fields},
		}
		e.H.Series.VMAMaxUtilRatio = 0.90
		chk := e.H.Check(wdeps.CheckCgroupThrottle)
		runWithFIFOGuard(t, mapsFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				PidsOnce:     func() []int { return []int{5003} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return staleSnap },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if e.H.Series.VMAMaxUtilRatio != 0.90 {
			t.Fatalf("VMAMaxUtilRatio=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
		}
	})
}
