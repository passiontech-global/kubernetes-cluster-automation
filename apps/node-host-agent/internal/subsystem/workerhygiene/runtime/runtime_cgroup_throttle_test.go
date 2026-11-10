// runtime_cgroup_throttle_test.go — cgroup-pod-throttle cgroup-pod-throttle
// guard coverage: pod memory.pressure/memory.events throttle
// detection (suppressed while the node-wide PSI thrash latch is
// active), the pids.max utilization gauge and the pids.events:max
// fork-denial deltas.
package runtime_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// mkPodSlice lays down one pod cgroup dir with the files the guard
// reads — rel is the dir path relative to the cgroup root
// (e.g. "kubepods.slice/kubepods-burstable.slice/
// kubepods-burstable-pod<uid>.slice").
func mkPodSlice(t *testing.T, cgRoot, rel, psiAvg60, memEventsHigh,
	pidsCur, pidsMax, pidsEventsMax string) {

	t.Helper()
	dir := filepath.Join(cgRoot, rel)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), fmt.Sprintf(
		"some avg10=1.00 avg60=%s avg300=1.00 total=0\n"+
			"full avg10=1.00 avg60=%s avg300=1.00 total=0\n",
		psiAvg60, psiAvg60))
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"),
		fmt.Sprintf("low 0\nhigh %s\nmax 0\noom 0\noom_kill 0\n", memEventsHigh))
	wdepstest.WriteFile(t, filepath.Join(dir, "pids.current"), pidsCur+"\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "pids.max"), pidsMax+"\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "pids.events"),
		fmt.Sprintf("max %s\n", pidsEventsMax))
}

// TestCgroupThrottleDetectsMemoryHigh: a pod slice with
// memory.pressure full avg60 > 40 AND a growing memory.events:high
// counts as throttled on the SECOND sighting (the verdict is a
// delta) — the log names the pod uid with dashes restored.
func TestCgroupThrottleDetectsMemoryHigh(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod1111_2222_3333_4444_555555555555.slice")
	mkPodSlice(t, cg, slice, "55.00", "10", "20", "500", "0")
	env := &wdeps.CycleEnv{WorkerActive: true}
	run := func() {
		wdepstest.Check[*runtime.CgroupThrottleCheck](h,
			wdeps.CheckCgroupThrottle).Run(ctx, env)
	}

	run() // baseline — first sighting, no delta yet
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatal("throttled counted on the baseline cycle (no delta)")
	}
	// memory.events high grew 10 → 14 while avg60 stays hot.
	mkPodSlice(t, cg, slice, "55.00", "14", "20", "500", "0")
	run()
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("throttled=%d want 1 (high delta >0 under hot PSI)",
			h.PodCgroupMemoryThrottled)
	}
	if got := e.LogLines(t); !strings.Contains(got,
		"uid=1111-2222-3333-4444-555555555555") {
		t.Fatalf("log must name the pod uid with dashes restored:\n%s", got)
	}
	// Same counters again — high is flat so the delta is zero: no
	// recount even though avg60 is still hot.
	run()
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("throttled=%d want 1 (flat high = episode over)",
			h.PodCgroupMemoryThrottled)
	}
}

// TestCgroupThrottlePodMemoryHighThrottledEvent — W21-G2: the
// throttle verdict also lands a PodMemoryHighThrottled Warning on
// the owning Pod, deduped per pod slice and re-armed by a
// conclusive non-throttle cycle.
func TestCgroupThrottlePodMemoryHighThrottledEvent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "throttled", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	mkPodSlice(t, cg, slice, "55.00", "10", "20", "500", "0")
	env := &wdeps.CycleEnv{WorkerActive: true, Pods: []corev1.Pod{*pod}}
	run := func() {
		wdepstest.Check[*runtime.CgroupThrottleCheck](h,
			wdeps.CheckCgroupThrottle).Run(ctx, env)
	}

	run() // baseline — first sighting, no delta yet
	mkPodSlice(t, cg, slice, "55.00", "14", "20", "500", "0")
	run() // throttle verdict → first event
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "PodMemoryHighThrottled" {
		t.Fatalf("events=%+v want one PodMemoryHighThrottled", evs.Items)
	}
	if evs.Items[0].Regarding.Name != "throttled" {
		t.Fatalf("event regarding=%q want pod throttled",
			evs.Items[0].Regarding.Name)
	}
	// Same episode, high keeps growing — the dedupe marker holds.
	mkPodSlice(t, cg, slice, "55.00", "20", "20", "500", "0")
	run()
	evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("dedupe failed: %d events in one episode", len(evs.Items))
	}
	// Conclusive non-throttle cycle (avg60 cool, high flat) re-arms.
	mkPodSlice(t, cg, slice, "10.00", "20", "20", "500", "0")
	run()
	// A NEW throttle burst emits a fresh event — advance the clock
	// so the events.v1 name (<pod>.<nanos>) doesn't collide with
	// the first episode's on the frozen fixture clock.
	e.Now = e.Now.Add(time.Second)
	mkPodSlice(t, cg, slice, "60.00", "25", "20", "500", "0")
	run()
	evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("re-armed episode emitted %d events, want 2", len(evs.Items))
	}
}

// TestCgroupThrottleSuppressedUnderNodePSI: while the psi-memory-thrash node-wide
// psi-memory-thrash latch is active the pod-level counter stays
// put — the node event already owns the signal.
func TestCgroupThrottleSuppressedUnderNodePSI(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice",
		"kubepods-pod1111_2222_3333_4444_555555555555.slice")
	mkPodSlice(t, cg, slice, "60.00", "3", "10", "100", "0")
	h.State.Enter("psi-memory-thrash", "test")
	env := &wdeps.CycleEnv{WorkerActive: true}
	run := func() {
		wdepstest.Check[*runtime.CgroupThrottleCheck](h,
			wdeps.CheckCgroupThrottle).Run(ctx, env)
	}
	run()
	mkPodSlice(t, cg, slice, "60.00", "9", "10", "100", "0")
	run()
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatal("pod throttle counted while node-wide PSI thrash latched")
	}
}

// TestCgroupThrottlePidsRatioAndDenials: the gauge carries the WORST
// pids.current/pids.max across pod slices, and a growing
// pids.events:max logs the pod whose cgroup denied a fork.
func TestCgroupThrottlePidsRatioAndDenials(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	hot := filepath.Join("kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-podaaaa_bbbb_cccc_dddd_eeeeeeeeeeee.slice")
	calm := filepath.Join("kubepods.slice",
		"kubepods-podffff_0000_1111_2222_333333333333.slice")
	mkPodSlice(t, cg, hot, "1.00", "0", "400", "500", "1")
	mkPodSlice(t, cg, calm, "0.50", "0", "50", "1000", "0")
	env := &wdeps.CycleEnv{WorkerActive: true}
	run := func() {
		wdepstest.Check[*runtime.CgroupThrottleCheck](h,
			wdeps.CheckCgroupThrottle).Run(ctx, env)
	}

	run()
	if h.PodCgroupPIDsMaxUtilRatio != 0.8 {
		t.Fatalf("pids ratio=%v want 0.8 (400/500 is the worst)",
			h.PodCgroupPIDsMaxUtilRatio)
	}
	// pids.events:max grew → the denial log names the pod uid.
	mkPodSlice(t, cg, hot, "1.00", "0", "450", "500", "3")
	run()
	if got := e.LogLines(t); !strings.Contains(got,
		"fork denials +2") {
		t.Fatalf("missing fork-denial suspect line:\n%s", got)
	}
	if h.PodCgroupPIDsMaxUtilRatio != 0.9 {
		t.Fatalf("pids ratio=%v want 0.9 (450/500)",
			h.PodCgroupPIDsMaxUtilRatio)
	}
	// Unlimited pids.max ("max") never feeds the ratio.
	mkPodSlice(t, cg, hot, "1.00", "0", "99999", "max", "3")
	run()
	if h.PodCgroupPIDsMaxUtilRatio != 0.05 {
		t.Fatalf("pids ratio=%v want 0.05 (unlimited max excluded)",
			h.PodCgroupPIDsMaxUtilRatio)
	}
}

// TestCgroupThrottleDormant: no kubepods.slice (cgroup v1 or a
// node without pod slices) → the check aborts quietly and writes
// no series.
func TestCgroupThrottleDormant(t *testing.T) {
	e := fixture(t)
	h := e.H
	h.Cfg.Runtime.CgroupRoot = t.TempDir()
	wdepstest.Check[*runtime.CgroupThrottleCheck](h,
		wdeps.CheckCgroupThrottle).Run(context.Background(),
		&wdeps.CycleEnv{WorkerActive: true})
	if h.PodCgroupMemoryThrottled != 0 || h.PodCgroupPIDsMaxUtilRatio != 0 {
		t.Fatal("series written on a dormant (no kubepods.slice) cycle")
	}
}
