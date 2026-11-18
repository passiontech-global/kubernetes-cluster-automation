package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCPUCFSThrottleRequiresHostIdleAnd3Cycles(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cfs-pod", UID: "uid-cfs-1"},
	}
	e := fixture(t, pod)
	sliceDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice", "kubepods-poduid_cfs_1.slice")
	if err := os.MkdirAll(sliceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.pressure"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), "high 0\n")

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	// Case 1: Host CPU idle < 40% (10% idle) -> must NOT fire even when cfs throttled.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "stat"), "cpu  900 0 0 100 0 0 0 0 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"), "nr_periods 100\nnr_throttled 0\n")
	chk.Run(context.Background(), ce)
	for i := 1; i <= 3; i++ {
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "stat"),
			fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0 0 0\n", 900+i*900, 100+i*100))
		wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"),
			fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
	}
	if e.H.Series.PodCgroupCPUThrottled != 0 {
		t.Fatalf("fired while host CPU busy (<40%% idle): %d", e.H.Series.PodCgroupCPUThrottled)
	}

	// Case 2: Host CPU idle >= 40% (70% idle) for 3 consecutive cycles -> fires on 3rd cycle + emits Event.
	for i := 4; i <= 6; i++ {
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "stat"),
			fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0 0 0\n", 3600+(i-3)*300, 400+(i-3)*700))
		wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"),
			fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
		if i < 6 && e.H.Series.PodCgroupCPUThrottled != 0 {
			t.Fatalf("fired early on cycle %d", i-3)
		}
	}
	if e.H.Series.PodCgroupCPUThrottled != 1 {
		t.Fatalf("PodCgroupCPUThrottled = %d, want 1", e.H.Series.PodCgroupCPUThrottled)
	}
	evList, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evList.Items) != 1 || evList.Items[0].Reason != "PodCPUCFSThrottled" {
		t.Fatalf("expected 1 PodCPUCFSThrottled event, got %+v (err=%v)", evList.Items, err)
	}
}

// Burstable pods carry the CFS quota on container *.scope cgroups — the
// pod slice's own cpu.stat shows no throttling, so scanning only it misses.
func TestCPUCFSThrottleScansChildScopes(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "scope-pod", UID: "uid-cfs-scope"},
	}
	e := fixture(t, pod)
	sliceDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot,
		"kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-poduid_cfs_scope.slice")
	scopeDir := filepath.Join(sliceDir, "cri-containerd-abc.scope")
	if err := os.MkdirAll(scopeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Pod-level cpu.stat is quiet; the container scope is throttled.
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"),
		"nr_periods 100\nnr_throttled 0\n")
	wdepstest.WriteFile(t, filepath.Join(scopeDir, "cpu.stat"),
		"nr_periods 100\nnr_throttled 0\n")
	statPath := filepath.Join(e.ProcDir, "stat")
	wdepstest.WriteFile(t, statPath, "cpu  0 0 0 0 0 0 0 0\n")

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), ce) // baseline
	for i := 1; i <= 3; i++ {
		wdepstest.WriteFile(t, statPath,
			fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, filepath.Join(scopeDir, "cpu.stat"),
			fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
	}
	if e.H.Series.PodCgroupCPUThrottled != 1 {
		t.Fatalf("PodCgroupCPUThrottled=%d, want 1 from child scope", e.H.Series.PodCgroupCPUThrottled)
	}
	if !strings.Contains(e.LogLines(t), "cpu.stat") {
		t.Fatalf("missing CPU CFS suspect log:\n%s", e.LogLines(t))
	}
}

func TestVMAPressureRaisesMaxMapCountAndEmitsEvent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vma-pod", UID: "11111111-2222-3333-4444-555555555555"},
	}
	e := fixture(t, pod)
	kubepods := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	if err := os.MkdirAll(kubepods, 0o755); err != nil {
		t.Fatal(err)
	}

	sysVM := filepath.Join(e.ProcDir, "sys", "vm")
	if err := os.MkdirAll(sysVM, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysVM, "max_map_count"), "100\n")

	// Plant PID 500 with large VmSize (field 23 -> Fields[20]) and 90 VMA lines (0.90 >= 0.85).
	pidDir := filepath.Join(e.ProcDir, "500")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 20 dummy fields after "(app) ": state(0) .. starttime(19) vsize(20)
	fields := make([]string, 21)
	fields[0] = "S"
	for i := 1; i < 20; i++ {
		fields[i] = "0"
	}
	fields[20] = "1073741824"
	wdepstest.WriteFile(t, filepath.Join(pidDir, "stat"), "500 (java) "+strings.Join(fields, " ")+"\n")
	wdepstest.WriteFile(t, filepath.Join(pidDir, "cgroup"), "0::/kubepods.slice/kubepods-pod11111111_2222_3333_4444_555555555555.slice/cri-containerd-abc.scope\n")

	var mapsBuf strings.Builder
	for i := 0; i < 90; i++ {
		fmt.Fprintf(&mapsBuf, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
	}
	wdepstest.WriteFile(t, filepath.Join(pidDir, "maps"), mapsBuf.String())

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), ce)

	gotMax, err := os.ReadFile(filepath.Join(sysVM, "max_map_count"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(gotMax)) != "200" {
		t.Fatalf("vm.max_map_count=%q, want 200", string(gotMax))
	}
	if e.H.Series.VMAMaxUtilRatio < 0.44 || e.H.Series.VMAMaxUtilRatio > 0.46 {
		t.Fatalf("VMAMaxUtilRatio=%v, want 0.45 (90/200)", e.H.Series.VMAMaxUtilRatio)
	}
	evList, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evList.Items) != 1 || evList.Items[0].Reason != "PodVMAMapCountPressure" {
		t.Fatalf("expected 1 PodVMAMapCountPressure event, got %+v (err=%v)", evList.Items, err)
	}
}
