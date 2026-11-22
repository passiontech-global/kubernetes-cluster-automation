// runtime_cgroup_throttle_test.go — cgroup-pod-throttle cgroup-pod-throttle
// guard coverage: pod memory.pressure/memory.events throttle
// detection (suppressed while the node-wide PSI thrash latch is
// active), the pids.max utilization gauge and the pids.events:max
// fork-denial deltas.
package runtime_test

import (
	"context"
	"fmt"
	"os"
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
// counts as throttled after memThrottleConfirmCycles (2) consecutive
// delta cycles — the log names the pod uid with dashes restored.
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
	// First delta cycle (10 → 14): streak=1, gated behind 2 consecutive delta cycles.
	mkPodSlice(t, cg, slice, "55.00", "14", "20", "500", "0")
	run()
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("throttled=%d want 0 after 1 delta cycle (consecutive gating)",
			h.PodCgroupMemoryThrottled)
	}
	// Second consecutive delta cycle (14 → 18): streak=2 → fires.
	mkPodSlice(t, cg, slice, "55.00", "18", "20", "500", "0")
	run()
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("throttled=%d want 1 (2 consecutive high deltas >0 under hot PSI)",
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

// TestCgroupThrottlePodMemoryHighThrottledEvent — pod-cgroup-oomkill-metrics: the
// throttle verdict also lands a PodMemoryHighThrottled Warning on
// the owning Pod after 2 consecutive delta cycles, deduped per pod
// slice and re-armed by a conclusive non-throttle cycle.
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
	run() // 1st delta cycle → streak=1, no event yet
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 0 {
		t.Fatalf("events=%+v want 0 after 1 delta cycle", evs.Items)
	}
	mkPodSlice(t, cg, slice, "55.00", "16", "20", "500", "0")
	run() // 2nd consecutive delta cycle → throttle verdict → first event
	evs, err = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
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
	// A NEW throttle burst emits a fresh event after 2 consecutive delta
	// cycles — advance the clock so the events.v1 name (<pod>.<nanos>)
	// doesn't collide with the first episode's on the frozen fixture clock.
	e.Now = e.Now.Add(time.Second)
	mkPodSlice(t, cg, slice, "60.00", "25", "20", "500", "0")
	run() // 1st delta cycle of new episode → streak=1, no 2nd event yet
	evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("single delta cycle after re-arm emitted %d events, want 1", len(evs.Items))
	}
	mkPodSlice(t, cg, slice, "60.00", "30", "20", "500", "0")
	run() // 2nd consecutive delta cycle → emits 2nd event
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

// TestCgroupCFSThrottleSuspectLogUIDAndPruning verifies R3.6:
// SuspectLog creates a slash-free last-suspect-cgroup-cfs-<uid> file
// without ENOENT errors, rate-limits across cycles, and prunes the
// marker after the pod slice exits.
func TestCgroupCFSThrottleSuspectLogUIDAndPruning(t *testing.T) {
	uid := "11111111-2222-3333-4444-555555555555"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cfs-r36", UID: types.UID(uid)},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	sliceDir := filepath.Join(h.Cfg.Runtime.CgroupRoot, "kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	if err := os.MkdirAll(sliceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.pressure"),
		"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), "high 0\n")

	chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "stat"), "cpu  0 0 0 0 0 0 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"), "nr_periods 100\nnr_throttled 0\n")
	chk.Run(ctx, ce) // baseline
	for i := 1; i <= 4; i++ {
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "stat"),
			fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"),
			fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(ctx, ce)
	}

	suspectFile := filepath.Join(h.Cfg.WatchdogStateDir, "last-suspect-cgroup-cfs-"+uid)
	if _, err := os.Stat(suspectFile); err != nil {
		t.Fatalf("expected slash-free suspect marker %s: %v", suspectFile, err)
	}
	logBody := e.LogLines(t)
	if strings.Contains(logBody, "ENOENT") || strings.Contains(logBody, "state file write failed") {
		t.Fatalf("unexpected ENOENT/write failure in logs:\n%s", logBody)
	}
	// Cycles 3 and 4 both triggered CFS throttle, but SuspectLog cadence (1h)
	// must emit only 1 suspect line across both cycles.
	if cnt := strings.Count(logBody, "throttled=80/100"); cnt != 1 {
		t.Fatalf("expected 1 rate-limited suspect log line, got %d:\n%s", cnt, logBody)
	}

	// Pod exits -> slice directory removed -> next cycle prunes last-suspect-cgroup-cfs-<uid>.
	if err := os.RemoveAll(sliceDir); err != nil {
		t.Fatal(err)
	}
	chk.Run(ctx, ce)
	if _, err := os.Stat(suspectFile); !os.IsNotExist(err) {
		t.Fatalf("expected suspect marker %s to be pruned after pod exit, err=%v", suspectFile, err)
	}
	if !h.State.RateOK("last-suspect-cgroup-cfs-"+uid, time.Hour) {
		t.Fatal("expected RateOK to be open after pruning (RAM lastSpent must also be pruned)")
	}
}

// TestCgroupThrottleAndSubprocOOMSharedSliceCache verifies that running
// CgroupThrottleCheck followed by SubprocOOMCheck shares pod slice reads
// without losing container scope OOM detection or pruning behavior.
func TestCgroupThrottleAndSubprocOOMSharedSliceCache(t *testing.T) {
	uid := wdepstest.UIDA
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "shared-pod", UID: types.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	cg := e.H.Cfg.Runtime.CgroupRoot
	slice := filepath.Join("kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	scope := filepath.Join(cg, slice, "cri-containerd-shared1.scope")
	mkPodSlice(t, cg, slice, "1.00", "0", "10", "100", "0")
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"), "oom_kill 1\noom_group_kill 0\n")
	wdepstest.WriteFile(t, filepath.Join(scope, "cgroup.procs"), "5001\n")

	cgChk := wdepstest.Check[*runtime.CgroupThrottleCheck](e.H, wdeps.CheckCgroupThrottle)
	oomChk := wdepstest.Check[*runtime.SubprocOOMCheck](e.H, wdeps.CheckSubprocOOM)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	ctx := context.Background()

	// Baseline cycle: CgroupThrottleCheck populates cache, SubprocOOMCheck consumes it.
	cgChk.Run(ctx, ce)
	oomChk.Run(ctx, ce)

	// Kill cycle: oom_kill advances while PID 1 stays 5001.
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"), "oom_kill 2\noom_group_kill 1\n")
	cgChk.Run(ctx, ce)
	oomChk.Run(ctx, ce)

	// Confirm cycle after 65s.
	e.Now = e.Now.Add(65 * time.Second)
	cgChk.Run(ctx, ce)
	oomChk.Run(ctx, ce)

	if e.H.ContainerSubprocessOOM != 1 {
		t.Fatalf("ContainerSubprocessOOM=%d want 1", e.H.ContainerSubprocessOOM)
	}
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var gotSubproc, gotGroup bool
	for _, ev := range evs.Items {
		if ev.Reason == "ContainerSubprocessOOMKilled" {
			gotSubproc = true
		}
		if ev.Reason == "ContainerCgroupOOMGroupKilled" {
			gotGroup = true
		}
	}
	if !gotSubproc || !gotGroup {
		t.Fatalf("missing expected events (subproc=%v group=%v): %+v", gotSubproc, gotGroup, evs.Items)
	}
}

func TestCgroupThrottleK1SomePSIConsecutiveCycleGating(t *testing.T) {
	t.Run("some_avg60_gt_25_with_max_delta", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "k1-some60", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		h := e.H
		ctx := context.Background()
		cg := t.TempDir()
		h.Cfg.Runtime.CgroupRoot = cg
		slice := filepath.Join("kubepods.slice",
			"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
		dir := filepath.Join(cg, slice)
		pressure := "some avg10=10.00 avg60=26.00 avg300=10.00 total=100\n" +
			"full avg10=1.00 avg60=1.00 avg300=1.00 total=10\n"
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), pressure)
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 10\n")

		chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

		chk.Run(ctx, ce) // Cycle 1: baseline
		if h.PodCgroupMemoryThrottled != 0 {
			t.Fatalf("cycle 1 throttled=%d want 0", h.PodCgroupMemoryThrottled)
		}

		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 15\n")
		chk.Run(ctx, ce) // Cycle 2: streak=1, gated
		if h.PodCgroupMemoryThrottled != 0 {
			t.Fatalf("cycle 2 (streak=1) throttled=%d want 0", h.PodCgroupMemoryThrottled)
		}
		evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 0 {
			t.Fatalf("cycle 2 emitted %d events, want 0", len(evs.Items))
		}

		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 20\n")
		chk.Run(ctx, ce) // Cycle 3: streak=2, fires
		if h.PodCgroupMemoryThrottled != 1 {
			t.Fatalf("cycle 3 (streak=2) throttled=%d want 1", h.PodCgroupMemoryThrottled)
		}
		evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != "PodMemoryHighThrottled" {
			t.Fatalf("cycle 3 events=%+v want 1 PodMemoryHighThrottled", evs.Items)
		}

		// Cycle 4: flat max -> no recount
		chk.Run(ctx, ce)
		if h.PodCgroupMemoryThrottled != 1 {
			t.Fatalf("cycle 4 (flat) throttled=%d want 1", h.PodCgroupMemoryThrottled)
		}
	})

	t.Run("some_avg10_gt_40_with_low_avg60_and_max_delta", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "k1-some10", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		h := e.H
		ctx := context.Background()
		cg := t.TempDir()
		h.Cfg.Runtime.CgroupRoot = cg
		slice := filepath.Join("kubepods.slice",
			"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
		dir := filepath.Join(cg, slice)
		pressure := "some avg10=41.00 avg60=10.00 avg300=5.00 total=100\n" +
			"full avg10=5.00 avg60=5.00 avg300=5.00 total=10\n"
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), pressure)
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 10\n")

		chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

		chk.Run(ctx, ce)
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 12\n")
		chk.Run(ctx, ce)
		if h.PodCgroupMemoryThrottled != 0 {
			t.Fatalf("cycle 2 throttled=%d want 0", h.PodCgroupMemoryThrottled)
		}
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 14\n")
		chk.Run(ctx, ce)
		if h.PodCgroupMemoryThrottled != 1 {
			t.Fatalf("cycle 3 throttled=%d want 1", h.PodCgroupMemoryThrottled)
		}
		evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != "PodMemoryHighThrottled" {
			t.Fatalf("cycle 3 events=%+v want 1 PodMemoryHighThrottled", evs.Items)
		}
	})

	t.Run("full_avg60_40_boundary_with_cool_some_does_not_fire", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "k1-boundary", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		h := e.H
		ctx := context.Background()
		cg := t.TempDir()
		h.Cfg.Runtime.CgroupRoot = cg
		slice := filepath.Join("kubepods.slice",
			"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
		dir := filepath.Join(cg, slice)
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"),
			"some avg10=10.00 avg60=10.00 total=100\nfull avg10=40.00 avg60=40.00 total=100\n")
		wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 10\nmax 0\n")

		chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		chk.Run(ctx, ce)
		for i := 1; i <= 4; i++ {
			wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), fmt.Sprintf("high %d\nmax 0\n", 10+i*10))
			chk.Run(ctx, ce)
		}
		if h.PodCgroupMemoryThrottled != 0 {
			t.Fatalf("exact avg60=40.00 boundary throttled=%d want 0", h.PodCgroupMemoryThrottled)
		}
		evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 0 {
			t.Fatalf("exact avg60=40.00 boundary emitted events=%+v want 0", evs.Items)
		}
	})
}

func TestCgroupThrottleK1SingleSpikeResetsStreak(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "k1-spike", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	dir := filepath.Join(cg, slice)
	hotPSI := "some avg10=45.00 avg60=30.00 avg300=10.00 total=100\nfull avg10=1.00 avg60=1.00 avg300=1.00 total=10\n"
	coolPSI := "some avg10=10.00 avg60=10.00 avg300=10.00 total=100\nfull avg10=1.00 avg60=1.00 avg300=1.00 total=10\n"

	chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), hotPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 10\n")
	chk.Run(ctx, ce) // baseline

	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 20\n")
	chk.Run(ctx, ce) // streak=1

	// Cool PSI resets streak even if counter grows.
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), coolPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 25\n")
	chk.Run(ctx, ce) // streak=0

	// Next hot delta starts back at streak=1 (must not fire).
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), hotPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 30\n")
	chk.Run(ctx, ce) // streak=1
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("after cool reset, single hot cycle throttled=%d want 0", h.PodCgroupMemoryThrottled)
	}

	// Flat counter resets streak to 0.
	chk.Run(ctx, ce) // streak=0
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 35\n")
	chk.Run(ctx, ce) // streak=1
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("after flat reset, single hot cycle throttled=%d want 0", h.PodCgroupMemoryThrottled)
	}

	// Second consecutive hot cycle fires.
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 40\n")
	chk.Run(ctx, ce) // streak=2
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("second consecutive hot cycle throttled=%d want 1", h.PodCgroupMemoryThrottled)
	}
}

func TestCgroupThrottleK1SomeOnlyAndCounterReset(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "k1-someonly", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	dir := filepath.Join(cg, slice)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"),
		"some avg10=10.00 avg60=30.00 total=100\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 5\nmax 0\n")

	chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	chk.Run(ctx, ce) // baseline
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 8\nmax 0\n")
	chk.Run(ctx, ce) // streak=1
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("cycle 2 throttled=%d want 0", h.PodCgroupMemoryThrottled)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 11\nmax 0\n")
	chk.Run(ctx, ce) // streak=2 -> fires
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("cycle 3 throttled=%d want 1", h.PodCgroupMemoryThrottled)
	}

	// Counter wrap/decrease yields delta=0, resets streak, and re-arms evented.
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 2\nmax 0\n")
	chk.Run(ctx, ce) // streak=0
	e.Now = e.Now.Add(time.Second)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 5\nmax 0\n")
	chk.Run(ctx, ce) // streak=1
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("cycle 5 (streak=1 after wrap) throttled=%d want 1", h.PodCgroupMemoryThrottled)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 8\nmax 0\n")
	chk.Run(ctx, ce) // streak=2 -> fires + 2nd event
	if h.PodCgroupMemoryThrottled != 2 {
		t.Fatalf("cycle 6 (streak=2) throttled=%d want 2", h.PodCgroupMemoryThrottled)
	}
	evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("events=%d want 2 after re-arm", len(evs.Items))
	}
}

func TestCgroupThrottleK1InconclusiveHoldsAndVanishedPrunes(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "k1-prune", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	dir := filepath.Join(cg, slice)
	hotPSI := "some avg10=10.00 avg60=30.00 total=100\n"

	chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), hotPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 10\n")
	chk.Run(ctx, ce) // Cycle 1: baseline

	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 15\n")
	chk.Run(ctx, ce) // Cycle 2: streak=1

	// Cycle 3: corrupt memory.pressure -> inconclusive, holds streak=1.
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), "corrupt\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 20\n")
	chk.Run(ctx, ce)
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("inconclusive cycle 3 throttled=%d want 0", h.PodCgroupMemoryThrottled)
	}

	// Cycle 4: restore memory.pressure -> held streak=1 advances to 2 and fires!
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), hotPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 25\n")
	chk.Run(ctx, ce)
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("cycle 4 throttled=%d want 1", h.PodCgroupMemoryThrottled)
	}

	// Cycle 5: corrupt memory.pressure -> inconclusive, holds evented marker.
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), "corrupt\n")
	chk.Run(ctx, ce)

	// Cycle 6: restore memory.pressure -> does NOT re-emit event.
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), hotPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 30\n")
	chk.Run(ctx, ce)
	if h.PodCgroupMemoryThrottled != 2 {
		t.Fatalf("cycle 6 throttled=%d want 2", h.PodCgroupMemoryThrottled)
	}
	evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("cycle 6 events=%d want 1 (evented held across inconclusive read)", len(evs.Items))
	}

	// Cycle 7: remove slice directory -> prunes prevMax, memStreak, and evented.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	chk.Run(ctx, ce)

	// Cycle 8: recreate same slice dir with fresh baseline max=10 -> must NOT inherit prevMax/memStreak/evented.
	e.Now = e.Now.Add(time.Second)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"), hotPSI)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 10\n")
	chk.Run(ctx, ce) // baseline
	if h.PodCgroupMemoryThrottled != 2 {
		t.Fatalf("recreated baseline throttled=%d want 2", h.PodCgroupMemoryThrottled)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 15\n")
	chk.Run(ctx, ce) // streak=1
	if h.PodCgroupMemoryThrottled != 2 {
		t.Fatalf("recreated cycle 2 (streak=1) throttled=%d want 2", h.PodCgroupMemoryThrottled)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 20\n")
	chk.Run(ctx, ce) // streak=2 -> fires + 2nd event
	if h.PodCgroupMemoryThrottled != 3 {
		t.Fatalf("recreated cycle 3 (streak=2) throttled=%d want 3", h.PodCgroupMemoryThrottled)
	}
	evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("recreated cycle 3 events=%d want 2", len(evs.Items))
	}
}

func TestCgroupThrottleK1NodeThrashSuppressesAndResetsStreak(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "k1-latch", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	slice := filepath.Join("kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	dir := filepath.Join(cg, slice)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"),
		"some avg10=10.00 avg60=30.00 total=100\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 10\n")

	chk := wdepstest.Check[*runtime.CgroupThrottleCheck](h, wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	chk.Run(ctx, ce) // Cycle 1: baseline
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 15\n")
	chk.Run(ctx, ce) // Cycle 2: streak=1

	// Latch active -> suppresses and resets memStreak to 0.
	h.State.Enter("psi-memory-thrash", "test")
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 20\n")
	chk.Run(ctx, ce)
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("throttled=%d want 0 while latched", h.PodCgroupMemoryThrottled)
	}

	// Latch clears -> must require 2 clean consecutive cycles.
	h.State.Exit("psi-memory-thrash", nil)
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 25\n")
	chk.Run(ctx, ce) // streak=1
	if h.PodCgroupMemoryThrottled != 0 {
		t.Fatalf("first clean cycle after latch throttled=%d want 0", h.PodCgroupMemoryThrottled)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"), "high 0\nmax 30\n")
	chk.Run(ctx, ce) // streak=2 -> fires
	if h.PodCgroupMemoryThrottled != 1 {
		t.Fatalf("second clean cycle after latch throttled=%d want 1", h.PodCgroupMemoryThrottled)
	}
	evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 || evs.Items[0].Reason != "PodMemoryHighThrottled" {
		t.Fatalf("events=%+v want 1 PodMemoryHighThrottled", evs.Items)
	}
}
