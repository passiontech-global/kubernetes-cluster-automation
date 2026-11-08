// collect_clock_conntrack_test.go — H1 adjtimex clock series and H2 conntrack table-pressure series.

package hostmetrics

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
	testutil.WriteFile(t, cfg.ConntrackCountFile, "230000\n")
	testutil.WriteFile(t, cfg.ConntrackMaxFile, "262144\n")
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
	testutil.WriteFile(t, cfg.ConntrackCountFile, "42\n")
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
	testutil.WriteFile(t, cfg.ConntrackCountFile, "10\n")
	testutil.WriteFile(t, cfg.ConntrackMaxFile, "0\n")
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
	testutil.WriteFile(t, cfg.ConntrackCountFile, "not-a-number\n")
	testutil.WriteFile(t, cfg.ConntrackMaxFile, "\n")
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

// --- W12-KR3: node_exporter-named nf_conntrack stat series ---

// The per-CPU stat table carries insert_failed + drop + early_drop
// hex columns; the node_exporter-named twins emit insert_failed
// verbatim and fold early_drop into drop.
func TestConntrackStatNodeExporterSeries(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, cfg.ConntrackStatFile,
		"  entries  searched found insert insert_failed drop early_drop\n"+
			"00000ed4  00000000 00000000 00000000 0000000a 00000004 00000002\n"+
			"00000ed5  00000000 00000000 00000000 00000014 00000002 00000001\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	// hex sums: 0xa+0x14 = 30 insert_failed; drop 0x4+0x2 = 6,
	// early_drop 0x2+0x1 = 3 → drop_total folds to 9.
	if v, ok := counterValue(t, c,
		"node_nf_conntrack_stat_insert_failed_total", node); !ok || v != 30 {
		t.Fatalf("nf insert_failed=%v ok=%v want 30", v, ok)
	}
	if v, ok := counterValue(t, c,
		"node_nf_conntrack_stat_drop_total", node); !ok || v != 9 {
		t.Fatalf("nf drop=%v ok=%v want 9 (drop 6 + early_drop 3)", v, ok)
	}
	// The legacy host_agent series stay strict drop-column (6).
	if v, ok := counterValue(t, c,
		"node_host_agent_conntrack_drops_total", node); !ok || v != 6 {
		t.Fatalf("legacy drops=%v ok=%v want 6 (drop only)", v, ok)
	}
}

func TestConntrackStatNodeExporterAbsentWithoutFile(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "missing")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_nf_conntrack_stat_insert_failed_total",
		"node_nf_conntrack_stat_drop_total",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without the stat file", name)
		}
	}
}

// --- Clocksource non-TSC drift gauge + kvm-clock restore ---

// clocksourceFixture wires the two sysfs seams into a temp dir and
// writes the given contents ("" = leave the file absent).
func clocksourceFixture(t *testing.T, cfg Config, current, available string) Config {
	t.Helper()
	dir := t.TempDir()
	cfg.ClocksourceCurrentFile = filepath.Join(dir, "current_clocksource")
	cfg.ClocksourceAvailableFile = filepath.Join(dir, "available_clocksource")
	if current != "" {
		testutil.WriteFile(t, cfg.ClocksourceCurrentFile, current+"\n")
	}
	if available != "" {
		testutil.WriteFile(t, cfg.ClocksourceAvailableFile, available+"\n")
	}
	return cfg
}

func clocksourceLabels(current string) map[string]string {
	return map[string]string{"node": "node-a", "clocksource": current}
}

func TestClocksourceGaugeTscHealthy(t *testing.T) {
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "tsc", "tsc hpet acpi_pm")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("tsc")); !ok || v != 0 {
		t.Fatalf("non_tsc=%v ok=%v want 0 (tsc active)", v, ok)
	}
}

func TestClocksourceGaugeKvmClockHealthy(t *testing.T) {
	// current == kvm-clock is the DESIRED clock on KVM hosts — the
	// drift gauge must not flag it just because tsc is also
	// available (the literal "current != tsc" reading would emit a
	// permanent 1 on every VM node).
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "kvm-clock", "tsc hpet acpi_pm kvm-clock")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("kvm-clock")); !ok || v != 0 {
		t.Fatalf("non_tsc=%v ok=%v want 0 (kvm-clock active)", v, ok)
	}
}

func TestClocksourceGaugeDriftedOffTsc(t *testing.T) {
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "hpet", "tsc hpet acpi_pm")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("hpet")); !ok || v != 1 {
		t.Fatalf("non_tsc=%v ok=%v want 1 (hpet active, tsc available)", v, ok)
	}
	// No kvm-clock in available → no restore write.
	if b, err := os.ReadFile(cfg.ClocksourceCurrentFile); err != nil ||
		string(b) != "hpet\n" {
		t.Fatalf("current_clocksource=%q err=%v want untouched hpet", b, err)
	}
}

func TestClocksourceRestoreKvmClock(t *testing.T) {
	// hpet current + kvm-clock available = the lost-pvclock-vDSO
	// drift → the collector writes kvm-clock back and the gauge
	// flags the drift for this scrape.
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "hpet", "tsc hpet acpi_pm kvm-clock")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("hpet")); !ok || v != 1 {
		t.Fatalf("non_tsc=%v ok=%v want 1 (hpet drifted)", v, ok)
	}
	b, err := os.ReadFile(cfg.ClocksourceCurrentFile)
	if err != nil || string(b) != "kvm-clock\n" {
		t.Fatalf("current_clocksource=%q err=%v want kvm-clock restore", b, err)
	}
}

func TestClocksourceNoFalsePositiveWithoutFastClock(t *testing.T) {
	// An arch whose available set has neither tsc nor kvm-clock
	// (no invariant TSC) must stay 0 — hpet there is the best the
	// hardware offers.
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "hpet", "hpet acpi_pm")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("hpet")); !ok || v != 0 {
		t.Fatalf("non_tsc=%v ok=%v want 0 (no fast clock exists)", v, ok)
	}
}

func TestClocksourceAvailableUnreadable(t *testing.T) {
	// available missing: fall back to the current-clock name alone
	// — hpet/acpi_pm/jiffies degrade, tsc stays healthy.
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "acpi_pm", "")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("acpi_pm")); !ok || v != 1 {
		t.Fatalf("non_tsc=%v ok=%v want 1 (acpi_pm, available unreadable)", v, ok)
	}

	cfg2, _ := fixture(t)
	cfg2 = clocksourceFixture(t, cfg2, "tsc", "")
	c2 := New(cfg2)
	if v, ok := metricValue(t, c2, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("tsc")); !ok || v != 0 {
		t.Fatalf("non_tsc=%v ok=%v want 0 (tsc, available unreadable)", v, ok)
	}
}

func TestClocksourceAbsentWithoutCurrent(t *testing.T) {
	// current unreadable = inconclusive — absent series, no fake 0.
	cfg, _ := fixture(t)
	cfg = clocksourceFixture(t, cfg, "", "tsc hpet")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_clocksource_non_tsc",
		clocksourceLabels("tsc")); ok {
		t.Fatal("non_tsc emitted without current_clocksource")
	}
}

// --- Conntrack search_restart/invalid counters ---

func TestConntrackSearchRestartAndInvalidCounters(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, cfg.ConntrackStatFile,
		"  entries  searched found insert_failed drop early_drop search_restart invalid\n"+
			"00000ed4  00000000 00000000 0000000a 00000004 00000002 00000064 0000000c\n"+
			"00000ed5  00000000 00000000 00000014 00000002 00000001 00000032 00000008\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	// hex sums: search_restart 0x64+0x32 = 150; invalid 0xc+0x8 = 20.
	if v, ok := counterValue(t, c,
		"node_host_agent_conntrack_search_restarts_total", node); !ok || v != 150 {
		t.Fatalf("search_restarts=%v ok=%v want 150", v, ok)
	}
	if v, ok := counterValue(t, c,
		"node_host_agent_conntrack_invalid_total", node); !ok || v != 20 {
		t.Fatalf("invalid=%v ok=%v want 20", v, ok)
	}
}

func TestConntrackSearchRestartAbsentWithoutColumn(t *testing.T) {
	// An older kernel header without the columns → absent series.
	cfg, _ := fixture(t)
	cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, cfg.ConntrackStatFile,
		"entries searched found\n00000001 00000002 00000003\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_conntrack_search_restarts_total",
		"node_host_agent_conntrack_invalid_total",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without its column", name)
		}
	}
}
