// steal_entropy.go — cpu-steal-guard + kernel-entropy-check:
// two /proc reads exported through the node-exporter textfile
// channel (node_agent_* — the same convention pidfd.go's
// utilization gauges use), plus the state-cpu-steal-pressure latch.
// Both live on the latch ticker rather than the scrape path because
// the latch hysteresis counts consecutive CYCLES — only the ticker
// has those; a scrape landing mid-streak must not reset it.
// (Renamed from collect_steal_entropy.go in the split — it never
// was a scrape collector; the collect_ prefix was misleading.)
//
//   - cpu-steal-guard: the steal column of /proc/stat aggregated
//     across the cpuN rows → steal/total jiffie delta per tick →
//     node_agent_cpu_steal_ratio. A hypervisor squeezing the VM
//     presents as random application timeouts while every in-guest
//     load signal stays boring — >35% for 3 consecutive ticks
//     enters state-cpu-steal-pressure (CPUStealPressure), <15% for
//     2 ticks releases.
//   - kernel-entropy-check: /proc/sys/kernel/random/entropy_avail →
//     node_agent_kernel_entropy_avail_bits — an entropy pool near
//     empty stalls TLS handshakes and key generation without
//     touching any utilization signal.
package kernelfail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// cpu-steal-guard hysteresis: enter state-cpu-steal-pressure above
// 35% steal for 3 consecutive ticks, release below 15% for 2 — the
// asymmetric band keeps a flapping hypervisor from toggling the
// latch (and the NodeCondition built on it) every cycle.
const (
	cpuStealOnRatio    = 0.35
	cpuStealOffRatio   = 0.15
	cpuStealEnterTicks = 3
	cpuStealExitTicks  = 2
)

// Streak counter file names inside the watchdog state dir — same
// consecutive-* convention pidFDCountFile/clockSkewCountFile use —
// and the textfile name under the node-exporter textfile dir.
const (
	cpuStealHighCountFile = "cpu-steal-high-count"
	cpuStealLowCountFile  = "cpu-steal-low-count"
	stealEntropyPromName  = "node-agent-steal.prom"
)

// The aggregate "cpu " row is the kernel's own sum of every cpuN
// row — reading just it gives identical steal/total jiffies without
// walking N per-CPU rows on every 30s latch tick (the sum used to
// cost O(cpus × fields) parses for data the kernel already folded).

// /proc/stat cpu-column order after the label: user nice system
// idle iowait irq softirq steal guest guest_nice. The guest columns
// are SUBSETS of user/nice — summing them into total would inflate
// the denominator and under-report steal. Kernels predating steal
// accounting ship only 8 columns; the row then contributes 0 steal
// jiffies and the file never latches — correct, there is nothing
// to report.
const (
	cpuStealColumn = 7 // steal — the 8th cpu field
	cpuTotalThru   = 8 // total sums columns [0,8) — guests excluded
)

// procStatCPUSums reads the aggregate "cpu " row of /proc/stat —
// the kernel's own sum across every cpuN row, so the delta math is
// identical to summing the per-CPU rows it replaces. ok=false when
// the file is unreadable or carries no usable cpu row —
// inconclusive evidence must not move the latch (the
// kernelKeysUsedRatio rule).
func procStatCPUSums(path string) (steal, total uint64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "cpu" {
			continue
		}
		// Only columns [0,cpuTotalThru) matter — the aggregate row
		// that truncates earlier still counts what it has (steal
		// stays 0); a non-numeric field is skipped whole — never
		// emit junk (the procfs.ReadConntrackStat rule).
		var rowSteal, rowTotal uint64
		bad := false
		for i := 0; i < cpuTotalThru && i < len(f)-1; i++ {
			v, perr := strconv.ParseUint(f[i+1], 10, 64)
			if perr != nil {
				bad = true
				break
			}
			rowTotal += v
			if i == cpuStealColumn {
				rowSteal = v
			}
		}
		if bad {
			return 0, 0, false
		}
		return rowSteal, rowTotal, true
	}
	return 0, 0, false
}

// stealDelta is the cpu-steal jiffie-delta baseline — one slice of
// what used to be the Collector's shared mu-guarded fields: the
// steal ratio is a DELTA between consecutive latch ticks, so the
// previous /proc/stat sums live here. The consecutive-tick streaks
// live in state-dir counter files instead — a restart reseeding the
// baseline costs one tick, losing the streak would cost three. The
// mutex is private.
type stealDelta struct {
	mu        sync.Mutex
	prevSteal uint64
	prevTotal uint64
	prevOK    bool
}

// delta returns the steal/total jiffie delta since the previous
// call. The first call only seeds the baseline — a ratio needs two
// samples — and counter regression (jiffies wrap, proc remount)
// reseeds instead of emitting a garbage ratio.
func (d *stealDelta) delta(steal, total uint64) (float64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.prevOK || steal < d.prevSteal || total <= d.prevTotal {
		d.prevSteal, d.prevTotal, d.prevOK = steal, total, true
		return 0, false
	}
	ds, dt := steal-d.prevSteal, total-d.prevTotal
	d.prevSteal, d.prevTotal = steal, total
	return float64(ds) / float64(dt), true
}

// cpuStealDelta reads the /proc/stat sums and folds them into the
// jiffie-delta baseline — see stealDelta.delta for the seeding and
// regression rules.
func (r *Runner) cpuStealDelta() (float64, bool) {
	steal, total, ok := procStatCPUSums(
		filepath.Join(r.deps.ProcRoot, "stat"))
	if !ok {
		return 0, false
	}
	return r.steal.delta(steal, total)
}

// kernelEntropyAvail reads the kernel entropy pool fill — bits,
// straight out of the sysctl.
func (r *Runner) kernelEntropyAvail() (float64, bool) {
	return r.readProcFloat("sys/kernel/random/entropy_avail")
}

// updateStealEntropy is the ticker half of both checks: exports the
// textfile gauges, then drives the state-cpu-steal-pressure
// hysteresis. An inconclusive steal read (baseline still seeding,
// proc gone) leaves streaks and latch alone — the same rule the
// other latch updaters follow; the streaks live in state-dir
// counter files so an agent restart doesn't silently reset them.
func (r *Runner) updateStealEntropy() {
	ratio, ratioOK := r.cpuStealDelta()
	entropy, entropyOK := r.kernelEntropyAvail()
	r.writeStealEntropyProm(ratio, ratioOK, entropy, entropyOK)
	if !ratioOK {
		return
	}
	latchPath := r.deps.Store.Path(latchdefs.LatchCPUStealPressure)
	switch {
	case ratio > cpuStealOnRatio:
		r.deps.Store.ResetCounter(cpuStealLowCountFile)
		if n := r.deps.Store.Incr(cpuStealHighCountFile); n >= cpuStealEnterTicks {
			r.ensureStateLatch(latchPath,
				latchdefs.LatchFilePrefix+latchdefs.LatchCPUStealPressure,
				fmt.Sprintf("steal_ratio=%.3f", ratio))
		}
	case ratio < cpuStealOffRatio:
		r.deps.Store.ResetCounter(cpuStealHighCountFile)
		if n := r.deps.Store.Incr(cpuStealLowCountFile); n < cpuStealExitTicks {
			return
		}
		// Exit self-gates on the file existing and logs STATE-EXIT.
		r.deps.Store.Exit(latchdefs.LatchCPUStealPressure, nil)
		// The exit streak is consumed — a later re-entry must
		// build its own 2-tick release, not inherit this count.
		r.deps.Store.ResetCounter(cpuStealLowCountFile)
	default:
		// Inside the hysteresis band neither streak is alive —
		// the latch state itself holds.
		r.deps.Store.ResetCounter(cpuStealHighCountFile)
		r.deps.Store.ResetCounter(cpuStealLowCountFile)
	}
}

// writeStealEntropyProm renders node_agent_cpu_steal_ratio and
// node_agent_kernel_entropy_avail_bits into the node-exporter
// textfile dir — each series only when its own source parsed (no
// fake 0s — the collectFileFD rule). Nothing is installed when
// neither parsed: an empty file would still carry stale family
// headers to node_exporter. Write failures log at Debug — the
// 30s ticker must not spam the watchdog tail on an unwritable
// mount (the writeKernelUtilProm rule).
func (r *Runner) writeStealEntropyProm(ratio float64, ratioOK bool,
	entropy float64, entropyOK bool) {
	if !ratioOK && !entropyOK {
		return
	}
	var b promfile.Builder
	if ratioOK {
		b.Gauge("node_agent_cpu_steal_ratio",
			"Steal/total jiffie delta across the /proc/stat cpuN rows — hypervisor CPU starvation.",
			ratio)
	}
	if entropyOK {
		b.Gauge("node_agent_kernel_entropy_avail_bits",
			"Kernel entropy pool fill — /proc/sys/kernel/random/entropy_avail.", entropy)
	}
	dir := r.textfileDir()
	_ = promfile.WriteLogged(dir, stealEntropyPromName,
		[]byte(b.String()), func(dir, _ string, err error) {
			logger().Warn("hostmetrics: steal/entropy textfile install failed",
				"dir", dir, "error", err)
		})
}
