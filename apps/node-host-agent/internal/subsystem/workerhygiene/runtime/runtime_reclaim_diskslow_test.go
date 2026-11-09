// runtime_reclaim_diskslow_test.go — coverage for the existing
// runtime guards: the targeted memory.reclaim on hot kubepods.slice
// children (cgroup-dying-reclaim) and the disk-slow-io DiskSlowIO
// gray-failure latch (io-pressure-throttler).
package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- targeted-memory-reclaim: targeted child-slice reclaim ---

// TestCgroupDyingReclaimsHotChildren: while the root/kubepods
// aggregate reclaim runs as before, first-level kubepods.slice
// children carrying nr_dying_descendants > 100 get their own
// memory.reclaim write — children under the threshold are left
// alone.
func TestCgroupDyingReclaimsHotChildren(t *testing.T) {
	e := fixture(t)
	h := e.H
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	kp := filepath.Join(cg, "kubepods.slice")
	wdepstest.WriteFile(t, filepath.Join(cg, "cgroup.stat"),
		"nr_dying_descendants 7000\n")
	wdepstest.WriteFile(t, filepath.Join(kp, "cgroup.stat"),
		"nr_dying_descendants 300\n")
	// One hot QoS child, one quiet one.
	wdepstest.WriteFile(t, filepath.Join(kp, "kubepods-burstable.slice",
		"cgroup.stat"), "nr_dying_descendants 150\n")
	wdepstest.WriteFile(t, filepath.Join(kp, "kubepods-besteffort.slice",
		"cgroup.stat"), "nr_dying_descendants 50\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "drop_caches"), "0\n")
	env := &wdeps.CycleEnv{WorkerActive: true}

	// ConsecNeeded=2 cycles to confirm the latch and run reclaim.
	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), env)
	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), env)

	if got := nhReadFile(t, filepath.Join(kp,
		"kubepods-burstable.slice", "memory.reclaim")); got != "256M\n" {
		t.Fatalf("hot child memory.reclaim=%q want \"256M\\n\"", got)
	}
	if _, err := os.Stat(filepath.Join(kp,
		"kubepods-besteffort.slice", "memory.reclaim")); !os.IsNotExist(err) {
		t.Fatal("quiet child got a targeted reclaim write")
	}
	if got := testutil.ToFloat64(
		h.Actions.WithLabelValues(wdeps.CheckCgroupDying, "reclaim_child")); got != 1 {
		t.Fatalf("reclaim_child actions=%v want 1", got)
	}
}

// --- disk-slow-io: disk-slow-io latch ---

// writeDiskIO lays down one sda diskstats row — counters are
// cumulative, so each call grows wrIOS/wrTicks to keep the
// per-cycle delta math producing a constant await.
func writeDiskIO(t *testing.T, e *env, wrIOS, wrTicks uint64) {
	t.Helper()
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "diskstats"), fmt.Sprintf(
		"   8       0 sda 1000 200 8000 500 %d 100 6000 %d 0 2000 5000\n",
		wrIOS, wrTicks))
}

func writeIOPSI(t *testing.T, e *env, avg60 float64) {
	t.Helper()
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "pressure", "io"),
		fmt.Sprintf("some avg10=1.00 avg60=1.00 avg300=1.00 total=0\n"+
			"full avg10=1.00 avg60=%.2f avg300=5.00 total=0\n", avg60))
}

// TestDiskSlowIOLatchAfterFiveCycles: per-disk write await >200ms
// AND PSI io avg60 >= 25% for 5 consecutive cycles enters
// state-disk-slow-io; recovery exits it. Latch-only — the
// throttler half is not involved (empty pid sweep).
func TestDiskSlowIOLatchAfterFiveCycles(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	writeIOPSI(t, e, 30.0)
	writeDiskIO(t, e, 100, 1000)
	env := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     wdepstest.PidsOf(),
	}
	run := func() {
		wdepstest.Check[*runtime.IOPressureCheck](h,
			wdeps.CheckIOPressure).Run(ctx, env)
	}
	latch := filepath.Join(e.StateDir, "state-disk-slow-io")

	run() // baseline — seeds lastDisk, no delta yet
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on the baseline cycle")
	}
	// +3000ms wrTicks over +10 wrIOS per cycle → 300ms await each.
	for i := 1; i <= 5; i++ {
		e.Now = e.Now.Add(time.Minute)
		writeDiskIO(t, e, 100+uint64(10*i), 1000+uint64(3000*i))
		run()
		if i < 5 {
			if _, err := os.Stat(latch); !os.IsNotExist(err) {
				t.Fatalf("latch early at cycle %d (<5)", i)
			}
		}
	}
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("state-disk-slow-io missing after 5 slow cycles")
	}
	// Recovery: flat counters + quiet PSI → latch exits, streak resets.
	e.Now = e.Now.Add(time.Minute)
	writeIOPSI(t, e, 5.0)
	run()
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("disk-slow-io latch not cleared on recovery")
	}
}

// TestDiskSlowIONeedsBothSignals: high await alone (quiet PSI) and
// high PSI alone (fast disk) must NOT latch — the gray failure is
// the conjunction.
func TestDiskSlowIONeedsBothSignals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		avg60  float64
		tickMs uint64 // per-cycle wrTicks delta over +10 wrIOS
	}{
		{"slow_disk_quiet_psi", 5.0, 3000}, // 300ms await, PSI 5%
		{"hot_psi_fast_disk", 60.0, 100},   // 10ms await, PSI 60%
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			h := e.H
			ctx := context.Background()
			writeIOPSI(t, e, tc.avg60)
			writeDiskIO(t, e, 100, 1000)
			env := &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     wdepstest.PidsOf(),
			}
			run := func() {
				wdepstest.Check[*runtime.IOPressureCheck](h,
					wdeps.CheckIOPressure).Run(ctx, env)
			}
			run() // baseline
			for i := 1; i <= 6; i++ {
				e.Now = e.Now.Add(time.Minute)
				writeDiskIO(t, e, 100+uint64(10*i),
					1000+uint64(int64(tc.tickMs)*int64(i)))
				run()
			}
			if _, err := os.Stat(filepath.Join(e.StateDir,
				"state-disk-slow-io")); !os.IsNotExist(err) {
				t.Fatal("disk-slow-io latched on a single-signal degrade")
			}
		})
	}
}
