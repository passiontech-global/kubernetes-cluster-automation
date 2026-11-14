// pidfd.go — pid-fd-pressure updatePidFDPressure: pid/thread/fd utilization
// ratios → state-pid-fd-pressure (KernelResourceExhaustion) + the
// node_agent_*_utilization_ratio textfile gauges (the node_agent metric
// channel — same convention the controllerhygiene textfile channel
// uses — adding a prometheus desc means a row in the parent's
// domains.go domainTable, and the textfile channel needs no
// registry change). The kernelfail contract overview lives in
// kernelfail.go.
package kernelfail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// kernelProcPressureRatio/Needed arm state-pid-fd-pressure —
// 90% utilization for 3 consecutive latch ticks.
const (
	kernelProcPressureRatio  = 0.90
	kernelProcPressureNeeded = 3
)

// Marker/state file name inside the watchdog state dir.
const pidFDCountFile = "pid-fd-pressure-count"

// --- pid-fd-pressure: pid/thread/fd exhaustion ---

// kernelProcRatios computes the three utilization ratios the
// state-pid-fd-pressure latch and the node_agent_* textfile gauges
// share:
//
//	pids    — live /proc/<pid> dirs / pid_max
//	threads — loadavg "running/total" entities / threads-max
//	filefd  — file-nr allocated / max
//	pty     — pty/nr over pty/max (pty-exhaustion-guard — pty exhaustion wedges
//	          every new TTY/session open cluster-wide)
//
// Each ratio carries its own ok flag — a source that didn't parse
// must not emit a fake 0 gauge (the collectFileFD rule); ok=false
// overall means NO source parsed — inconclusive evidence must not
// move the latch (the kernelKeysUsedRatio rule).
func (r *Runner) kernelProcRatios() (pids, threads, filefd, pty float64,
	pidsOK, threadsOK, fdOK, ptyOK, ok bool) {
	seen := false
	if entries, err := os.ReadDir(r.deps.ProcRoot); err == nil {
		tasks := 0
		for _, e := range entries {
			if e.IsDir() && procfs.IsDigits(e.Name()) {
				tasks++
			}
		}
		if max, mok := r.readProcFloat("sys/kernel/pid_max"); mok && max > 0 {
			pids, pidsOK, seen = float64(tasks)/max, true, true
		}
	}
	if b, err := os.ReadFile(filepath.Join(r.deps.ProcRoot, "loadavg")); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 4 {
			if pair := strings.Split(f[3], "/"); len(pair) == 2 {
				if total, err := strconv.ParseFloat(pair[1], 64); err == nil {
					if max, mok := r.readProcFloat("sys/kernel/threads-max"); mok && max > 0 {
						threads, threadsOK, seen = total/max, true, true
					}
				}
			}
		}
	}
	if b, err := os.ReadFile(r.deps.FileNRFile); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			alloc, errA := strconv.ParseFloat(f[0], 64)
			max, errM := strconv.ParseFloat(f[2], 64)
			if errA == nil && errM == nil && max > 0 {
				filefd, fdOK, seen = alloc/max, true, true
			}
		}
	}
	// pty-exhaustion-guard: /dev/ptmx exhaustion is the same class as fd pressure
	// — nr pseudo-terminals in use over the pty.max ceiling. Both
	// files are sysctl-tunable; a missing pair is inconclusive, not
	// zero.
	if nr, nok := r.readProcFloat("sys/kernel/pty/nr"); nok {
		if max, mok := r.readProcFloat("sys/kernel/pty/max"); mok && max > 0 {
			pty, ptyOK, seen = nr/max, true, true
		}
	}
	return pids, threads, filefd, pty, pidsOK, threadsOK, fdOK, ptyOK, seen
}

// readProcFloat reads one numeric file under ProcRoot.
func (r *Runner) readProcFloat(elem string) (float64, bool) {
	b, err := os.ReadFile(filepath.Join(r.deps.ProcRoot, elem))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// updatePidFDPressure drives state-pid-fd-pressure (pid-fd-pressure →
// KernelResourceExhaustion): the WORST of the pid/thread/fd ratios
// above 0.90 for kernelProcPressureNeeded consecutive latch ticks.
// The count persists in the state dir so an agent restart keeps the
// streak; any sub-threshold or inconclusive-free tick resets it.
// The node_agent_*_utilization_ratio gauges ride the same evaluation
// into the node-exporter textfile.
func (r *Runner) updatePidFDPressure() {
	pids, threads, filefd, pty, pidsOK, threadsOK, fdOK, ptyOK, ok :=
		r.kernelProcRatios()
	if !ok {
		return // inconclusive — leave count, latch and gauges alone
	}
	r.writeKernelUtilProm(pids, threads, filefd, pty,
		pidsOK, threadsOK, fdOK, ptyOK)
	worst, what := -1.0, ""
	for _, v := range []struct {
		v    float64
		ok   bool
		name string
	}{{pids, pidsOK, "pids"}, {threads, threadsOK, "threads"},
		{filefd, fdOK, "file-nr"}, {pty, ptyOK, "pty"}} {
		if v.ok && v.v > worst {
			worst, what = v.v, v.name
		}
	}
	latchPath := r.deps.Store.Path(latchdefs.LatchPIDFDPressure)
	if worst > kernelProcPressureRatio {
		// Store.Incr — the shared consecutive-counter core (steal/
		// entropy parity): locked read+increment+write on the same
		// <state dir>/pid-fd-pressure-count file the hand-rolled
		// read/write managed; a failed write loses the streak (never
		// invents one) and the Store logs the failure.
		n := r.deps.Store.Incr(pidFDCountFile)
		if n >= kernelProcPressureNeeded {
			r.ensureStateLatch(latchPath, latchdefs.LatchFilePrefix+latchdefs.LatchPIDFDPressure,
				fmt.Sprintf("%s ratio=%.3f", what, worst))
		} else {
			// A latch from an earlier episode outliving a fresh
			// sub-threshold streak can't happen (the else branch
			// clears it) — release defensively anyway (Exit no-ops
			// when the file is absent).
			r.deps.Store.Exit(latchdefs.LatchPIDFDPressure, nil)
		}
		return
	}
	// Below threshold — reset the streak and release the latch
	// (Exit logs STATE-EXIT, the filelog's transition contract).
	r.deps.Store.ResetCounter(pidFDCountFile)
	r.deps.Store.Exit(latchdefs.LatchPIDFDPressure, nil)
}

// --- node_agent textfile metrics (node-exporter channel) ---

// textfileDir resolves the node-exporter textfile drop dir through
// the shared promfile.TextfileDir derivation — NODE_HOST_AGENT_
// TEXTFILE_DIR when set, else <HostRoot>/var/lib/node-exporter/
// textfile. textfileDirOverride wins over both in tests
// (controllerhygiene's kineTextfileDirOverride parity).
func (r *Runner) textfileDir() string {
	if r.deps.TextfileDir != "" {
		return r.deps.TextfileDir
	}
	return promfile.TextfileDir(r.deps.HostRoot)
}

// writeKernelUtilProm emits the pid-fd-pressure utilization gauges —
// node_agent_{pids,threads,file_nr}_utilization_ratio. Each series
// appears only when its source parsed (no fake 0s — the
// collectFileFD rule). promfile.Write stages + renames so
// node_exporter never reads a partial file. Failures log at Warn
// (converged with the other textfile emitters):
func (r *Runner) writeKernelUtilProm(pids, threads, filefd, pty float64,
	pidsOK, threadsOK, fdOK, ptyOK bool) {
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
	if ptyOK {
		b.Gauge("node_agent_pty_utilization_ratio",
			"kernel.pty.nr over kernel.pty.max — pty exhaustion pressure.", pty)
	}
	dir := r.textfileDir()
	_ = promfile.WriteLogged(dir,
		"node-agent-kernel.prom", []byte(b.String()), func(dir, _ string, err error) {
			logger().Warn("hostmetrics: kernel textfile install failed",
				"dir", dir, "error", err)
		})
}
