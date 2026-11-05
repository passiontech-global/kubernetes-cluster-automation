package apiprober

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// backendState tracks per-backend consecutive-cycle counters — the
// in-memory equivalent of the shell script's $STATE_DIR files
// (qfail-, frozen-, fail-, ok-, drained-).
type backendState struct {
	qfail     int   // consecutive query failures (TCP alive)
	frozen    int   // consecutive identical rv_cache while rv_now grows
	fail      int   // consecutive gap > GapMin
	ok        int   // consecutive fully-fresh cycles
	prevCache int64 // last observed rv_cache
	hasPrev   bool
	drained   bool // we issued disable (or are tracking it)
	// probeErr is the edge-latch key ("<cache class>|<live class>")
	// of the probe-side failure last Warn'd — the PROBE-ERR line
	// logs once on state-change (entering probe_error, or the class
	// pair changing), and a recovery line logs once when the cycle
	// stops being all-probe-side. A multi-hour credential outage
	// logs a handful of lines, not one per cycle.
	probeErr string
}

func (p *Prober) stateFor(name string) *backendState {
	st, ok := p.states[name]
	if !ok {
		st = &backendState{}
		p.states[name] = st
	}
	return st
}

// pruneStaleBackends drops in-memory probe state and every
// per-backend metric series for names no longer present in
// discovery — a backend retired from api-local-lb would otherwise
// pin its p.states entry and its label values on the registry
// forever. Only runs when discovery returned rows — never on
// discover failure or an empty backend list.
func (p *Prober) pruneStaleBackends(backends []backend) {
	live := make(map[string]bool, len(backends))
	for _, b := range backends {
		live[b.Name] = true
	}
	for name := range p.states {
		if live[name] {
			continue
		}
		delete(p.states, name)
		p.rvGap.DeleteLabelValues(name)
		p.enabled.DeleteLabelValues(name)
		logger().Info("apiprober: backend left HAProxy discovery — pruned "+
			"probe state and metric series",
			"backend", name)
		// probeFailures/actions carry a second label (phase|action)
		// — drop every series whose backend label matches.
		p.probeFailures.DeletePartialMatch(prometheus.Labels{"backend": name})
		p.actions.DeletePartialMatch(prometheus.Labels{"backend": name})
	}
}

// --- watchdog state files (module 34 parity) ---
// The host node-watchdog stack reads these: 06-kubelet-watch-wedge
// gates k0sworker restarts on state-apiserver-backend-stale-<ip>, and
// lib.sh prom_emit turns apibe-gap-<ip> into
// node_watchdog_apiserver_backend_gap{backend="<ip-dashed>"}. The
// suffix is the backend IP with dots replaced by dashes
// (shell ${beh//./-}) — NOT the server name.

// watchdogDir returns the configured state dir when it exists on disk
// this cycle, else "". An empty/missing dir disables all file ops
// silently — test environments and non-watchdog nodes.
func (p *Prober) watchdogDir() string {
	d := p.cfg.WatchdogStateDir
	if d == "" {
		return ""
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		return ""
	}
	return d
}

// dashedIP maps a backend addr to the watchdog file suffix:
// "10.0.0.1:6443" → "10-0-0-1".
func dashedIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // Addr without a port — use it raw
	}
	return strings.ReplaceAll(host, ".", "-")
}

// writeGapFile records the last measured rv gap for prom_emit.
// Best-effort: a write failure is logged, never fatal.
func (p *Prober) writeGapFile(dir string, b backend, gap int64) {
	f := dir + "/apibe-gap-" + dashedIP(b.Addr)
	if err := hostutil.WriteFileAtomicBytes(f,
		[]byte(strconv.FormatInt(gap, 10)+"\n")); err != nil {
		logger().Warn("watchdog gap file write failed",
			"file", f, "backend", b.Name, "error", err,
		)
	}
}

// latchStale creates state-apiserver-backend-stale-<ip> — state_enter
// semantics: create only if absent, content = current epoch.
func (p *Prober) latchStale(dir string, b backend) {
	f := dir + "/" + hoststate.LatchFilePrefix +
		hoststate.LatchAPIServerBackendStalePrefix + dashedIP(b.Addr)
	if _, err := os.Stat(f); err == nil {
		return
	}
	if err := hostutil.WriteFileAtomicBytes(f,
		[]byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n")); err != nil {
		logger().Warn("watchdog stale latch write failed",
			"file", f, "backend", b.Name, "error", err,
		)
	}
}

// clearStale removes the stale latch — state_exit semantics, called
// only on a fully-fresh cycle (hysteresis: inconclusive cycles keep
// whatever exists). not-exist is ignored.
func (p *Prober) clearStale(dir string, b backend) {
	f := dir + "/" + hoststate.LatchFilePrefix +
		hoststate.LatchAPIServerBackendStalePrefix + dashedIP(b.Addr)
	if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
		logger().Warn("watchdog stale latch remove failed",
			"file", f, "backend", b.Name, "error", err,
		)
	}
}

// pruneWatchdogFiles deletes apibe-gap-* and state-apiserver-backend-
// stale-* files whose dashed-IP is no longer among the discovered
// direct backends — a backend retired from api-local-lb would
// otherwise leave its latch/gap file latched forever (false NPD/prom
// signal, the shell's prune block parity). Only runs when discovery
// returned rows — never on discover failure or an empty backend list.
func (p *Prober) pruneWatchdogFiles(dir string, backends []backend) {
	keep := make(map[string]bool, len(backends))
	for _, b := range backends {
		if !b.vip() {
			keep[dashedIP(b.Addr)] = true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger().Warn("watchdog state dir scan failed — stale files not pruned",
			"dir", dir, "error", err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		var suffix string
		switch {
		case strings.HasPrefix(name, "apibe-gap-"):
			suffix = strings.TrimPrefix(name, "apibe-gap-")
		case strings.HasPrefix(name, hoststate.LatchFilePrefix+
			hoststate.LatchAPIServerBackendStalePrefix):
			suffix = strings.TrimPrefix(name, hoststate.LatchFilePrefix+
				hoststate.LatchAPIServerBackendStalePrefix)
		default:
			continue
		}
		if !keep[suffix] {
			if err := os.Remove(dir + "/" + name); err != nil {
				logger().Warn("watchdog stale file prune failed",
					"file", name, "dir", dir, "error", err,
				)
			}
		}
	}
}
