// collect_clock_conntrack_test.go — H1 adjtimex clock series and H2 conntrack table-pressure series.

package hostmetrics

import (
	"math"
	"testing"

	"golang.org/x/sys/unix"
)

// --- H1: clock sync (adjtimex) ---

func TestClockUnsynchronizedAndEstError(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.adjtimexFn = func(tx *unix.Timex) (int, error) {
		tx.Status = unix.STA_UNSYNC
		tx.Esterror = 750_000 // µs → 0.75 s
		return 0, nil
	}
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_clock_unsynchronized",
		node); !ok || v != 1 {
		t.Fatalf("clock_unsynchronized=%v ok=%v want 1 (STA_UNSYNC)", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_clock_estimated_error_seconds",
		node); !ok || v != 0.75 {
		t.Fatalf("estimated_error=%v ok=%v want 0.75 (µs→s)", v, ok)
	}
}

func TestClockSynchronizedEmitsZero(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.adjtimexFn = func(tx *unix.Timex) (int, error) {
		tx.Status = unix.STA_PLL // synced flags, no STA_UNSYNC
		tx.Esterror = 12_000
		return 0, nil
	}
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_clock_unsynchronized",
		node); !ok || v != 0 {
		t.Fatalf("clock_unsynchronized=%v ok=%v want explicit 0", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_clock_estimated_error_seconds",
		node); !ok || v != 0.012 {
		t.Fatalf("estimated_error=%v ok=%v want 0.012", v, ok)
	}
}

func TestClockAbsentWhenAdjtimexFails(t *testing.T) {
	cfg, _ := fixture(t)
	// fixture stub already errors — inconclusive read must emit no
	// series rather than a fake "synchronized" 0.
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if _, ok := metricValue(t, c, "node_host_agent_clock_unsynchronized",
		node); ok {
		t.Fatal("clock_unsynchronized emitted despite adjtimex error")
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_clock_estimated_error_seconds", node); ok {
		t.Fatal("estimated_error emitted despite adjtimex error")
	}
}

// --- H2: conntrack table pressure ---

func TestConntrackMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.ConntrackCountFile, "230000\n")
	write(t, cfg.ConntrackMaxFile, "262144\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}

	if v, ok := metricValue(t, c, "node_host_agent_conntrack_entries",
		node); !ok || v != 230000 {
		t.Fatalf("entries=%v ok=%v want 230000", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_limit",
		node); !ok || v != 262144 {
		t.Fatalf("limit=%v ok=%v want 262144", v, ok)
	}
	want := 230000.0 / 262144.0
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_used_ratio",
		node); !ok || math.Abs(v-want) > 1e-9 {
		t.Fatalf("used_ratio=%v ok=%v want %v", v, ok, want)
	}
}

func TestConntrackAbsentWithoutFiles(t *testing.T) {
	cfg, _ := fixture(t)
	// A node without the conntrack module has neither file → all
	// three series absent (no fake 0).
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_conntrack_entries",
		"node_host_agent_conntrack_limit",
		"node_host_agent_conntrack_used_ratio",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without proc files", name)
		}
	}
}

func TestConntrackPartialData(t *testing.T) {
	cfg, _ := fixture(t)
	// Only the count file reads — entries emits, limit+ratio stay
	// absent (each gauge tracks its own source).
	write(t, cfg.ConntrackCountFile, "42\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_entries",
		node); !ok || v != 42 {
		t.Fatalf("entries=%v ok=%v want 42", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_conntrack_limit",
		node); ok {
		t.Fatal("limit emitted without the max file")
	}
	if _, ok := metricValue(t, c, "node_host_agent_conntrack_used_ratio",
		node); ok {
		t.Fatal("ratio emitted without the max file")
	}
}

func TestConntrackZeroLimitSkipsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.ConntrackCountFile, "10\n")
	write(t, cfg.ConntrackMaxFile, "0\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_conntrack_limit",
		node); !ok || v != 0 {
		t.Fatalf("limit=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_conntrack_used_ratio",
		node); ok {
		t.Fatal("ratio emitted with a zero limit (div-by-zero)")
	}
}

func TestConntrackMalformedSkipped(t *testing.T) {
	cfg, _ := fixture(t)
	write(t, cfg.ConntrackCountFile, "not-a-number\n")
	write(t, cfg.ConntrackMaxFile, "\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_conntrack_entries",
		"node_host_agent_conntrack_limit",
		"node_host_agent_conntrack_used_ratio",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted for malformed data", name)
		}
	}
}
