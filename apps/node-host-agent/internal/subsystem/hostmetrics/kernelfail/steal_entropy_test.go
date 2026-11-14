// steal_entropy_test.go — /proc/stat steal parsing, the
// cpu-steal-pressure hysteresis + STATE-ENTER log line, the entropy
// textfile gauge, and the clock-stepped-at marker. (Moved with
// steal_entropy.go — was collect_steal_entropy_test.go.)
package kernelfail

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
// the aggregate "cpu " row the parser reads (its sums ARE the cpuN
// sum — the kernel folds them) plus a cpu0 row for realism.
func writeProcStat(t *testing.T, procRoot string, steal, idle uint64) {
	t.Helper()
	row := func(label string) string {
		return fmt.Sprintf("%s 0 0 0 %d 0 0 0 %d 0 0\n", label, idle, steal)
	}
	testutil.WriteFile(t, filepath.Join(procRoot, "stat"),
		row("cpu ")+row("cpu0"))
}

func TestProcStatCPUSums(t *testing.T) {
	file := filepath.Join(t.TempDir(), "stat")
	if _, _, ok := procStatCPUSums(file); ok {
		t.Fatal("missing stat file reported ok")
	}
	testutil.WriteFile(t, file,
		// The aggregate "cpu " row carries the cpuN sums — the
		// parser reads it alone. Steal = column 8; the two
		// trailing guest columns must stay out of total.
		"cpu  10 0 10 80 0 0 0 4 2 1\n"+
			"cpu0 5 0 5 40 0 0 0 2 1 0\n"+
			"cpu1 5 0 5 40 0 0 0 2 1 1\n"+
			"intr 1234\n")
	steal, total, ok := procStatCPUSums(file)
	if !ok {
		t.Fatal("stat not parsed")
	}
	if steal != 4 || total != 104 {
		t.Fatalf("steal=%d total=%d want 4/104 (guest cols excluded)",
			steal, total)
	}
	// A row with a non-numeric column is skipped whole.
	testutil.WriteFile(t, file, "cpu0 5 0 x 40 0 0 0 2\n")
	if _, _, ok := procStatCPUSums(file); ok {
		t.Fatal("malformed cpu row parsed ok")
	}
}

func TestCPUStealLatchHysteresis(t *testing.T) {
	f := kfixture(t)
	latch := filepath.Join(f.deps.StateDir, "state-cpu-steal-pressure")

	writeProcStat(t, f.deps.ProcRoot, 0, 1000)
	f.r.updateStealEntropy() // seeds the baseline — no delta, no tick

	// Three consecutive 50% ticks must arm the latch; two must not.
	for i := 0; i < cpuStealEnterTicks; i++ {
		writeProcStat(t, f.deps.ProcRoot, uint64(50*(i+1)), uint64(1000+50*(i+1)))
		f.r.updateStealEntropy()
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
	log := testutil.ReadFile(t, f.log)
	if !strings.Contains(log,
		"STATE-ENTER: cpu-steal-pressure (steal_ratio=0.500)") {
		t.Fatalf("missing STATE-ENTER line:\n%s", log)
	}

	// Steal flat while total grows → ratio 0 → two ticks release.
	writeProcStat(t, f.deps.ProcRoot, 150, 1250)
	f.r.updateStealEntropy()
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch dropped after a single low tick")
	}
	writeProcStat(t, f.deps.ProcRoot, 150, 1350)
	f.r.updateStealEntropy()
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept after 2 low ticks")
	}
}

func TestStealEntropyPromGauges(t *testing.T) {
	f := kfixture(t)
	td := t.TempDir()
	f.r.deps.TextfileDir = td
	testutil.WriteFile(t, filepath.Join(f.deps.ProcRoot,
		"sys/kernel/random/entropy_avail"), "3789\n")

	writeProcStat(t, f.deps.ProcRoot, 0, 1000)
	f.r.updateStealEntropy() // baseline — entropy already emits
	prom := testutil.ReadFile(t, filepath.Join(td,
		stealEntropyPromName))
	if !strings.Contains(prom,
		"node_agent_kernel_entropy_avail_bits 3789") {
		t.Fatalf("entropy gauge missing:\n%s", prom)
	}
	if strings.Contains(prom, "node_agent_cpu_steal_ratio") {
		t.Fatal("steal gauge emitted without a delta sample")
	}

	writeProcStat(t, f.deps.ProcRoot, 40, 1100) // delta 40/140 ≈ 0.2857
	f.r.updateStealEntropy()
	prom = testutil.ReadFile(t, filepath.Join(td,
		stealEntropyPromName))
	got := ""
	for ln := range strings.SplitSeq(prom, "\n") {
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
	f := kfixture(t)
	// Clock is re-stubbed post-construction on purpose — the Store
	// observes it through the shared timex.Cell, and the makestep
	// rate budget must age past clockSkewMakestepGap between
	// attempts.
	now := time.Unix(1_700_000_000, 0)
	f.deps.Clock.Set(func() time.Time { return now })
	orig := f.r.deps.RunHostCmd
	defer func() { f.r.deps.RunHostCmd = orig }()
	markStep := func(fail bool) {
		f.r.deps.RunHostCmd = func(ctx context.Context, argv ...string) (string, error) {
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
	marker := filepath.Join(f.deps.StateDir, clockSteppedMarkerFile)

	// A FAILED makestep must not arm the healer's window — the
	// budget was still spent (rate_spend parity), so the retry
	// needs the gap to elapse.
	markStep(true)
	f.r.checkClockSkew(context.Background())
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("clock-stepped-at written on failed makestep")
	}

	now = now.Add(11 * time.Minute)
	markStep(false)
	f.r.checkClockSkew(context.Background())
	got := strings.TrimSpace(testutil.ReadFile(t, marker))
	if _, err := strconv.ParseInt(got, 10, 64); err != nil {
		t.Fatalf("clock-stepped-at content %q not an epoch", got)
	}
}
