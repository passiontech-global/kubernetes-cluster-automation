// pidfd.go — W10-KR2 updatePidFDPressure: pid/thread/fd utilization
// ratios → state-pid-fd-pressure (KernelResourceExhaustion) + the
// node_agent_*_utilization_ratio textfile gauges (the W10 metric
// channel — same convention the controllerhygiene textfile channel
// uses — adding a prometheus desc means a row in domains.go's
// domainTable, and the textfile channel needs no registry change).
// The Wave-10 contract overview lives in kernel_failure_latches.go.
package hostmetrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// kernelProcPressureRatio/Needed arm state-pid-fd-pressure —
// 90% utilization for 3 consecutive latch ticks.
const (
	kernelProcPressureRatio  = 0.90
	kernelProcPressureNeeded = 3
)

// Marker/state file name inside WatchdogStateDir.
const pidFDCountFile = "pid-fd-pressure-count"

// textfileDirOverride wins over the HostRoot-derived textfile
// dir in tests (controllerhygiene's kineTextfileDirOverride parity).
var textfileDirOverride string

// --- W10-KR2: pid/thread/fd exhaustion ---

// kernelProcRatios computes the three utilization ratios the
// state-pid-fd-pressure latch and the node_agent_* textfile gauges
// share:
//
//	pids    — live /proc/<pid> dirs / pid_max
//	threads — loadavg "running/total" entities / threads-max
//	filefd  — file-nr allocated / max
//
// Each ratio carries its own ok flag — a source that didn't parse
// must not emit a fake 0 gauge (the collectFileFD rule); ok=false
// overall means NO source parsed — inconclusive evidence must not
// move the latch (the kernelKeysUsedRatio rule).
func (l *Latches) kernelProcRatios() (pids, threads, filefd float64,
	pidsOK, threadsOK, fdOK, ok bool) {
	seen := false
	if entries, err := os.ReadDir(l.c.cfg.ProcRoot); err == nil {
		tasks := 0
		for _, e := range entries {
			if e.IsDir() && pidDirRe.MatchString(e.Name()) {
				tasks++
			}
		}
		if max, mok := l.readProcFloat("sys/kernel/pid_max"); mok && max > 0 {
			pids, pidsOK, seen = float64(tasks)/max, true, true
		}
	}
	if b, err := os.ReadFile(filepath.Join(l.c.cfg.ProcRoot, "loadavg")); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 4 {
			if pair := strings.Split(f[3], "/"); len(pair) == 2 {
				if total, err := strconv.ParseFloat(pair[1], 64); err == nil {
					if max, mok := l.readProcFloat("sys/kernel/threads-max"); mok && max > 0 {
						threads, threadsOK, seen = total/max, true, true
					}
				}
			}
		}
	}
	if b, err := os.ReadFile(l.c.cfg.FileNRFile); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			alloc, errA := strconv.ParseFloat(f[0], 64)
			max, errM := strconv.ParseFloat(f[2], 64)
			if errA == nil && errM == nil && max > 0 {
				filefd, fdOK, seen = alloc/max, true, true
			}
		}
	}
	return pids, threads, filefd, pidsOK, threadsOK, fdOK, seen
}

// readProcFloat reads one numeric file under ProcRoot.
func (l *Latches) readProcFloat(elem string) (float64, bool) {
	b, err := os.ReadFile(filepath.Join(l.c.cfg.ProcRoot, elem))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// updatePidFDPressure drives state-pid-fd-pressure (W10-KR2 →
// KernelResourceExhaustion): the WORST of the pid/thread/fd ratios
// above 0.90 for kernelProcPressureNeeded consecutive latch ticks.
// The count persists in the state dir so an agent restart keeps the
// streak; any sub-threshold or inconclusive-free tick resets it.
// The node_agent_*_utilization_ratio gauges ride the same evaluation
// into the node-exporter textfile.
func (l *Latches) updatePidFDPressure() {
	pids, threads, filefd, pidsOK, threadsOK, fdOK, ok := l.kernelProcRatios()
	if !ok {
		return // inconclusive — leave count, latch and gauges alone
	}
	l.writeKernelUtilProm(pids, threads, filefd, pidsOK, threadsOK, fdOK)
	worst, what := -1.0, ""
	for _, r := range []struct {
		v    float64
		ok   bool
		name string
	}{{pids, pidsOK, "pids"}, {threads, threadsOK, "threads"}, {filefd, fdOK, "file-nr"}} {
		if r.ok && r.v > worst {
			worst, what = r.v, r.name
		}
	}
	countPath := l.statePath(pidFDCountFile)
	latchPath := l.c.state.Path(hoststate.LatchPIDFDPressure)
	if worst > kernelProcPressureRatio {
		n := int64(1)
		if b, err := os.ReadFile(countPath); err == nil {
			if v, perr := strconv.ParseInt(
				strings.TrimSpace(string(b)), 10, 64); perr == nil {
				n = v + 1
			}
		}
		if err := os.WriteFile(countPath,
			[]byte(strconv.FormatInt(n, 10)+"\n"), 0o644); err != nil {
			logger().Debug("hostmetrics: pid-fd count write failed",
				"path", countPath, "error", err)
		}
		if n >= kernelProcPressureNeeded {
			l.ensureStateLatch(latchPath, hoststate.LatchFilePrefix+hoststate.LatchPIDFDPressure,
				fmt.Sprintf("%s ratio=%.3f", what, worst))
		} else {
			// A latch from an earlier episode outliving a fresh
			// sub-threshold streak can't happen (the else branch
			// clears it) — release defensively anyway (Exit no-ops
			// when the file is absent).
			l.c.state.Exit(hoststate.LatchPIDFDPressure, nil)
		}
		return
	}
	// Below threshold — reset the streak and release the latch
	// (Exit logs STATE-EXIT, the filelog's transition contract).
	_ = os.Remove(countPath)
	l.c.state.Exit(hoststate.LatchPIDFDPressure, nil)
}

// --- W10 textfile metrics (node-exporter channel) ---

// textfileDir resolves the node-exporter textfile drop dir —
// <HostRoot>/var/lib/node-exporter/textfile (the controllerhygiene
// textfile-dir override parity: K0sDir's sibling under the same
// convention).
func (l *Latches) textfileDir() string {
	if textfileDirOverride != "" {
		return textfileDirOverride
	}
	return filepath.Join(l.c.cfg.HostRoot,
		"var", "lib", "node-exporter", "textfile")
}

// writeKernelUtilProm emits the W10-KR2 utilization gauges —
// node_agent_{pids,threads,file_nr}_utilization_ratio. Each series
// appears only when its source parsed (no fake 0s — the
// collectFileFD rule). promfile.Write stages + renames so
// node_exporter never reads a partial file. Failures log at Debug:
// refreshLatches runs every 30s and an unwritable mount must not
// spam the watchdog tail.
func (l *Latches) writeKernelUtilProm(pids, threads, filefd float64,
	pidsOK, threadsOK, fdOK bool) {
	var b promfile.Builder
	if pidsOK {
		b.Gauge("node_agent_pids_utilization_ratio",
			"Live /proc pid dirs over kernel.pid_max.", pids)
	}
	if threadsOK {
		b.Gauge("node_agent_threads_utilization_ratio",
			"loadavg total entities over kernel.threads-max.", threads)
	}
	if fdOK {
		b.Gauge("node_agent_file_nr_utilization_ratio",
			"file-nr allocated over maximum — fd table pressure.", filefd)
	}
	dir := l.textfileDir()
	if err := promfile.Write(dir,
		"node-agent-kernel.prom", []byte(b.String())); err != nil {
		logger().Debug("hostmetrics: kernel textfile install failed",
			"dir", dir, "error", err)
	}
}
