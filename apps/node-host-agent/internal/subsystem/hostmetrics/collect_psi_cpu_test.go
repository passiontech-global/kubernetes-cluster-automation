// collect_psi_cpu_test.go — PSI avg60 gauge/overload latch and the cpu-delivered probe.

package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- PSI overload (runner's node-overloaded) ---

func TestPSIGaugeAndOverloadLatch(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "cpu")
	c := New(cfg)

	write(t, cfg.PSIFile, "some avg10=10.00 avg60=45.50 avg300=20.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	v, ok := metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if !ok || v != 45.5 {
		t.Fatalf("psi=%v,%v want 45.5", v, ok)
	}
	latch := filepath.Join(dirs["state"], "state-node-overloaded")
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("overload latch not created at avg60>=40: %v", err)
	}
	// Hysteresis: 30% is between 40/25 — latch persists.
	write(t, cfg.PSIFile, "some avg10=5.00 avg60=30.00 avg300=10.00 total=9\n")
	metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped inside hysteresis band")
	}
	// Below 25 → released.
	write(t, cfg.PSIFile, "some avg10=1.00 avg60=20.00 avg300=5.00 total=4\n")
	metricValue(t, c, "node_watchdog_psi_cpu_some_avg60", map[string]string{})
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept below the 25% release threshold")
	}
}

func TestPSIUnreadableKeepsLatch(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.PSIFile = filepath.Join(t.TempDir(), "missing")
	latch := filepath.Join(dirs["state"], "state-node-overloaded")
	write(t, latch, "1\n")
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

// --- cpu-delivered probe ---

func TestCPUDeliveredEmitsAfterMeasure(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.CPUDeliveredInterval = time.Minute
	c := New(cfg)
	c.cfg.nowFn = func() time.Time { return time.Unix(1000, 0) }
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
