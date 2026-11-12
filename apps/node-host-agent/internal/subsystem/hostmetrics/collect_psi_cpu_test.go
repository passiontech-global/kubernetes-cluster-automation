// collect_psi_cpu_test.go — PSI avg60 gauge/overload latch and the cpu-delivered probe.

package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- PSI overload (runner's node-overloaded) ---

func TestPSIGaugeAndOverloadLatch(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "cpu")
	c := New(cfg)

	testutil.WriteFile(t, cfg.PSIFile, "some avg10=10.00 avg60=45.50 avg300=20.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	v, ok := metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if !ok || v != 45.5 {
		t.Fatalf("psi=%v,%v want 45.5", v, ok)
	}
	latch := filepath.Join(dirs["state"], "state-node-overloaded")
	// The gauge is scrape-side; the state-* latch is the ticker's
	// job — Collect is read-only, so the scrape above must NOT have
	// minted the latch file.
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("scrape wrote state-node-overloaded — Collect must stay read-only")
	}
	// Drive one refreshLatches pass (the Run() equivalent).
	c.Latches().refreshLatches(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("overload latch not created at avg60>=40: %v", err)
	}
	// Hysteresis: 30% is between 40/25 — latch persists.
	testutil.WriteFile(t, cfg.PSIFile, "some avg10=5.00 avg60=30.00 avg300=10.00 total=9\n")
	c.Latches().refreshLatches(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped inside hysteresis band")
	}
	// Below 25 → released.
	testutil.WriteFile(t, cfg.PSIFile, "some avg10=1.00 avg60=20.00 avg300=5.00 total=4\n")
	c.Latches().refreshLatches(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept below the 25% release threshold")
	}
}

func TestPSIUnreadableKeepsLatch(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "missing")
	latch := filepath.Join(dirs["state"], "state-node-overloaded")
	testutil.WriteFile(t, latch, "1\n")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_watchdog_psi_cpu_some_avg60",
		map[string]string{}); ok {
		t.Fatal("psi gauge emitted with unreadable PSI file")
	}
	// Inconclusive read → existing latch kept.
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped on unreadable PSI")
	}
}

// TestPSIMalformedValueAbsent: a garbage avg60 value is
// inconclusive — no gauge, no latch movement, never a fake 0.
func TestPSIMalformedValueAbsent(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "cpu")
	testutil.WriteFile(t, cfg.PSIFile,
		"some avg10=1.00 avg60=garbage avg300=5.00 total=1\n"+
			"full avg60=0.00 total=0\n")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_watchdog_psi_cpu_some_avg60",
		map[string]string{}); ok {
		t.Fatal("psi gauge emitted with a malformed avg60 value")
	}
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-node-overloaded")); !os.IsNotExist(err) {
		t.Fatal("malformed PSI latched node-overloaded")
	}
}

// --- cpu-delivered probe ---

func TestCPUDeliveredEmitsAfterMeasure(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.CPUDeliveredInterval = time.Minute
	c := New(cfg)
	c.cfg.Clock.Set(func() time.Time { return time.Unix(1000, 0) })
	c.cfg.cpuMeasure = func() (float64, float64, bool) { return 0.95, 0.32, true }

	// First scrape: probe launched async — wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if v, ok := metricValue(t, c, "node_cpu_delivered_ratio",
			map[string]string{}); ok {
			if v != 0.95 {
				t.Fatalf("ratio=%v want 0.95", v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cpu delivered ratio never emitted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if v, ok := metricValue(t, c, "node_cpu_delivered_probe_wall_seconds",
		map[string]string{}); !ok || v != 0.32 {
		t.Fatalf("wall=%v,%v want 0.32", v, ok)
	}
}

func TestCPUDeliveredAbsentBeforeMeasure(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// Blocked forever — no result, and the scrape still completes.
	c.cfg.cpuMeasure = func() (float64, float64, bool) {
		select {} // never returns — simulates a probe still running
	}
	if _, ok := metricValue(t, c, "node_cpu_delivered_ratio",
		map[string]string{}); ok {
		t.Fatal("ratio emitted before first completed measurement")
	}
}

// TestMeasureCPURealBusyLoop exercises the un-seamed probe. The
// value itself is the test host's CPU-delivery measurement, so only
// structural invariants are asserted — the same property the shell
// probe had.
func TestMeasureCPURealBusyLoop(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.cpuMeasure = nil // the real RUSAGE_THREAD busy-loop
	c := New(cfg)
	ratio, wall, ok := c.measureCPU()
	if !ok {
		t.Fatal("busy-loop probe reported failure")
	}
	if wall <= 0 || wall > cpuDeliveredMaxWall.Seconds() {
		t.Fatalf("wall=%v outside (0, %v]", wall, cpuDeliveredMaxWall)
	}
	if ratio <= 0 || ratio > 1 {
		t.Fatalf("ratio=%v outside (0,1]", ratio)
	}
	c.cpu.mu.Lock()
	sink := c.cpu.sink
	c.cpu.mu.Unlock()
	if sink == 0 {
		t.Fatal("busy-loop checksum sink never parked")
	}
}
