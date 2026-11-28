package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func writePodMemHighFixture(t *testing.T, cgRoot, sliceRel string, highCount, oomCount int64, someAvg60 float64) {
	t.Helper()
	dir := filepath.Join(cgRoot, "kubepods.slice", sliceRel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.events"),
		"low 0\nhigh "+strconv.FormatInt(highCount, 10)+"\nmax 0\noom 0\noom_kill "+strconv.FormatInt(oomCount, 10)+"\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "memory.pressure"),
		"some avg10=10.00 avg60="+strconv.FormatFloat(someAvg60, 'f', 2, 64)+" avg300=5.00 total=100\n"+
			"full avg10=2.00 avg60=5.00 avg300=1.00 total=50\n")
}

func TestCgroupMemoryHighThrottleDetectsAndClears(t *testing.T) {
	e := fixture(t)
	cgRoot := filepath.Join(t.TempDir(), "cgroup")
	e.H.Cfg.Runtime.CgroupRoot = cgRoot
	podSlice := "kubepods-burstable.slice/kubepods-burstable-pod1111_2222.slice"

	// Missing kubepods.slice aborts cleanly without latching.
	chk := e.H.Check(wdeps.CheckCgroupMemoryHighThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true}
	chk.Run(context.Background(), ce)
	if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupMemoryHighThrottle, "abort")); got != 1 {
		t.Fatalf("missing kubepods abort cycles = %v, want 1", got)
	}

	// Cycle 1: baseline high=100 -> delta 0, no latch.
	writePodMemHighFixture(t, cgRoot, podSlice, 100, 0, 22.0)
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle) {
		t.Fatal("latched on baseline cycle 1")
	}

	// Cycle 2: high=120 (+20), oom_kill=0, some avg60=22 -> streak 1/2 (not latched yet).
	writePodMemHighFixture(t, cgRoot, podSlice, 120, 0, 22.0)
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle) {
		t.Fatal("latched prematurely on streak 1/2")
	}

	// Cycle 3: high=145 (+25), oom_kill=0, some avg60=22 -> streak 2/2 -> latch, gauge=1, ACTION+suspect log.
	writePodMemHighFixture(t, cgRoot, podSlice, 145, 0, 22.0)
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle) {
		t.Fatal("expected LatchCgroupMemoryHighThrottle after 2 consecutive high-delta + PSI cycles")
	}
	if got := promtestutil.ToFloat64(e.H.CgroupMemoryHighThrottledPods); got != 1 {
		t.Fatalf("throttled gauge = %v, want 1", got)
	}
	logs := e.LogLines(t)
	if !strings.Contains(logs, "ACTION: cgroup-memory-high-throttle detected 1 silently throttled pod(s)") {
		t.Fatalf("missing ACTION log:\n%s", logs)
	}
	if !strings.Contains(logs, "suspect: cgroup-memory-high-throttle") {
		t.Fatalf("missing suspect log:\n%s", logs)
	}

	// Cycle 4: high delta stops -> cleared, gauge=0, latch exited.
	writePodMemHighFixture(t, cgRoot, podSlice, 145, 0, 5.0)
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle) {
		t.Fatal("expected LatchCgroupMemoryHighThrottle cleared when throttling stops")
	}
	if got := promtestutil.ToFloat64(e.H.CgroupMemoryHighThrottledPods); got != 0 {
		t.Fatalf("cleared throttled gauge = %v, want 0", got)
	}
}

func TestCgroupMemoryHighThrottleSkipsOOMKillAndNodeThrash(t *testing.T) {
	t.Run("skips-when-oom-kill-delta-nonzero", func(t *testing.T) {
		e := fixture(t)
		cgRoot := filepath.Join(t.TempDir(), "cgroup")
		e.H.Cfg.Runtime.CgroupRoot = cgRoot
		podSlice := "kubepods-pod3333_4444.slice"
		chk := e.H.Check(wdeps.CheckCgroupMemoryHighThrottle)
		ce := &wdeps.CycleEnv{WorkerActive: true}

		writePodMemHighFixture(t, cgRoot, podSlice, 10, 0, 30.0)
		chk.Run(context.Background(), ce)
		writePodMemHighFixture(t, cgRoot, podSlice, 20, 1, 30.0)
		chk.Run(context.Background(), ce)
		writePodMemHighFixture(t, cgRoot, podSlice, 30, 2, 30.0)
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle) {
			t.Fatal("must not latch silent memory.high throttle when OOMKills occurred")
		}
	})

	t.Run("skips-while-node-psi-thrash-latched", func(t *testing.T) {
		e := fixture(t)
		cgRoot := filepath.Join(t.TempDir(), "cgroup")
		e.H.Cfg.Runtime.CgroupRoot = cgRoot
		podSlice := "kubepods-pod5555_6666.slice"
		e.H.State.Enter(latchdefs.LatchPSIMemoryThrash, "node thrashing")
		chk := e.H.Check(wdeps.CheckCgroupMemoryHighThrottle)
		ce := &wdeps.CycleEnv{WorkerActive: true}

		writePodMemHighFixture(t, cgRoot, podSlice, 10, 0, 30.0)
		chk.Run(context.Background(), ce)
		writePodMemHighFixture(t, cgRoot, podSlice, 20, 0, 30.0)
		chk.Run(context.Background(), ce)
		writePodMemHighFixture(t, cgRoot, podSlice, 30, 0, 30.0)
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchCgroupMemoryHighThrottle) {
			t.Fatal("must not latch per-pod memory.high while node-wide psi-memory-thrash is active")
		}
	})
}
