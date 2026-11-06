// collect_steal_entropy_test.go — /proc/stat steal parsing, the
// cpu-steal-pressure hysteresis + STATE-ENTER log line, the entropy
// textfile gauge, and the clock-stepped-at marker.
package hostmetrics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// writeProcStat plants a /proc/stat body under the fixture ProcRoot:
// one aggregate row (which the parser must SKIP — its sums are the
// same as cpu0's here and would double-count) plus a single cpu0
// row whose steal and total (=idle+steal) the caller controls.
func writeProcStat(t *testing.T, cfg Config, steal, idle uint64) {
	t.Helper()
	row := func(label string) string {
		return fmt.Sprintf("%s 0 0 0 %d 0 0 0 %d 0 0\n", label, idle, steal)
	}
	testutil.WriteFile(t, filepath.Join(cfg.ProcRoot, "stat"),
		row("cpu ")+row("cpu0"))
}

func TestProcStatCPUSums(t *testing.T) {
	f := filepath.Join(t.TempDir(), "stat")
	if _, _, ok := procStatCPUSums(f); ok {
		t.Fatal("missing stat file reported ok")
	}
	testutil.WriteFile(t, f,
		// Aggregate row is identical to the cpuN sum — the parser
		// must not double-count it. Steal = column 8; the two
		// trailing guest columns must stay out of total.
		"cpu  10 0 10 80 0 0 0 4 2 1\n"+
			"cpu0 5 0 5 40 0 0 0 2 1 0\n"+
			"cpu1 5 0 5 40 0 0 0 2 1 1\n"+
			"intr 1234\n")
	steal, total, ok := procStatCPUSums(f)
	if !ok {
		t.Fatal("stat not parsed")
	}
	if steal != 4 || total != 104 {
		t.Fatalf("steal=%d total=%d want 4/104 (guest cols excluded)",
			steal, total)
	}
	// A row with a non-numeric column is skipped whole.
	testutil.WriteFile(t, f, "cpu0 5 0 x 40 0 0 0 2\n")
	if _, _, ok := procStatCPUSums(f); ok {
		t.Fatal("malformed cpu row parsed ok")
	}
}

func TestCPUStealLatchHysteresis(t *testing.T) {
	cfg, _ := fixture(t)
	logFile := filepath.Join(t.TempDir(), "watchdog.log")
	cfg.WatchdogLogFile = logFile
	c := New(cfg)
	l := c.Latches()
	latch := filepath.Join(cfg.WatchdogStateDir, "state-cpu-steal-pressure")

	writeProcStat(t, cfg, 0, 1000)
	l.updateStealEntropy() // seeds the baseline — no delta, no tick

	// Three consecutive 50% ticks must arm the latch; two must not.
	for i := 0; i < cpuStealEnterTicks; i++ {
		writeProcStat(t, cfg, uint64(50*(i+1)), uint64(1000+50*(i+1)))
		l.updateStealEntropy()
		if i < cpuStealEnterTicks-1 {
			if _, err := os.Stat(latch); !os.IsNotExist(err) {
				t.Fatalf("latch set early at tick %d", i+1)
			}
		}
	}
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("cpu-steal-pressure latch missing after 3 high ticks")
	}
	// The STATE-ENTER line is the nodereporter Event contract —
	// bare latch name + parenthesized evidence.
	log := testutil.ReadFile(t, logFile)
	if !strings.Contains(log,
		"STATE-ENTER: cpu-steal-pressure (steal_ratio=0.500)") {
		t.Fatalf("missing STATE-ENTER line:\n%s", log)
	}

	// Steal flat while total grows → ratio 0 → two ticks release.
	writeProcStat(t, cfg, 150, 1250)
	l.updateStealEntropy()
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped after a single low tick")
	}
	writeProcStat(t, cfg, 150, 1350)
	l.updateStealEntropy()
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept after 2 low ticks")
	}
}

func TestStealEntropyPromGauges(t *testing.T) {
	cfg, _ := fixture(t)
	textfileDirOverride = t.TempDir()
	c := New(cfg)
	l := c.Latches()
	testutil.WriteFile(t, filepath.Join(cfg.ProcRoot,
		"sys/kernel/random/entropy_avail"), "3789\n")

	writeProcStat(t, cfg, 0, 1000)
	l.updateStealEntropy() // baseline — entropy already emits
	prom := testutil.ReadFile(t, filepath.Join(textfileDirOverride,
		stealEntropyPromName))
	if !strings.Contains(prom,
		"node_agent_kernel_entropy_avail_bits 3789") {
		t.Fatalf("entropy gauge missing:\n%s", prom)
	}
	if strings.Contains(prom, "node_agent_cpu_steal_ratio") {
		t.Fatal("steal gauge emitted without a delta sample")
	}

	writeProcStat(t, cfg, 40, 1100) // delta 40/140 ≈ 0.2857
	l.updateStealEntropy()
	prom = testutil.ReadFile(t, filepath.Join(textfileDirOverride,
		stealEntropyPromName))
	got := ""
	for _, ln := range strings.Split(prom, "\n") {
		if strings.HasPrefix(ln, "node_agent_cpu_steal_ratio ") {
			got = strings.TrimPrefix(ln, "node_agent_cpu_steal_ratio ")
		}
	}
	v, err := strconv.ParseFloat(got, 64)
	if err != nil || v < 0.28 || v > 0.29 {
		t.Fatalf("steal ratio=%q err=%v want ~0.286", got, err)
	}
}

func TestClockSteppedMarker(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// nowFn is re-stubbed post-New on purpose — the Store observes
	// it through its Now closure, and the makestep rate budget must
	// age past clockSkewMakestepGap between attempts.
	now := time.Unix(1_700_000_000, 0)
	c.cfg.nowFn = func() time.Time { return now }
	orig := runHostCmd
	defer func() { runHostCmd = orig }()
	markStep := func(fail bool) {
		runHostCmd = func(ctx context.Context, argv ...string) (string, error) {
			if len(argv) > 1 && argv[1] == "makestep" {
				if fail {
					return "", fmt.Errorf("makestep rejected")
				}
				return "", nil
			}
			return "System time     : 3.0 seconds fast of NTP time\n" +
				"Leap status     : Not synchronised\n", nil
		}
	}
	marker := filepath.Join(cfg.WatchdogStateDir, clockSteppedMarkerFile)

	// A FAILED makestep must not arm the healer's window — the
	// budget was still spent (rate_spend parity), so the retry
	// needs the gap to elapse.
	markStep(true)
	c.Latches().checkClockSkew()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("clock-stepped-at written on failed makestep")
	}

	now = now.Add(11 * time.Minute)
	markStep(false)
	c.Latches().checkClockSkew()
	got := strings.TrimSpace(testutil.ReadFile(t, marker))
	if _, err := strconv.ParseInt(got, 10, 64); err != nil {
		t.Fatalf("clock-stepped-at content %q not an epoch", got)
	}
}
