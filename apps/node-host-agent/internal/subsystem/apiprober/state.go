package apiprober

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// backendState tracks per-backend consecutive-cycle counters — the
// restored $STATE_DIR contract of the shell script (qfail-, frozen-,
// fail-, ok-, drained- files). RAM stays authoritative during a run;
// the apibe-<counter>-<name> files in the watchdog state dir are the
// restart witness — loaded once per backend on its first cycle under
// a live dir (st.loaded) and flushed at every cycle end, so an agent
// restart resumes wedge streaks and the drained marker instead of
// re-arming them from zero. The family is namespaced apibe- for
// ownership clarity in the shared dir and keyed by backend NAME —
// the p.states key — not the dashed-IP suffix the cross-process
// files use: VIPs and static-only backends have no meaningful probe
// addr for an IP key to name. It is internal-only: the janitor
// reaps only state-* files and nothing else reads these, so the
// cross-process contract stays state-apiserver-backend-stale-*/
// apibe-gap-*.
type backendState struct {
	qfail     int   // consecutive query failures (TCP alive)
	frozen    int   // consecutive identical rv_cache while rv_now grows
	fail      int   // consecutive gap > GapMin
	ok        int   // consecutive fully-fresh cycles
	prevCache int64 // last observed rv_cache — the frozen baseline
	hasPrev   bool
	drained   bool // we issued disable (or are tracking it)
	// loaded latches once the on-disk apibe-* files have been folded
	// in — the load runs at most once per backend per process
	// lifetime (first cycle with a live watchdog dir); RAM-only
	// entries (dir unset/missing then) stay false — nothing to load.
	loaded bool
	// probeErr is the edge-latch key ("<cache class>|<live class>")
	// of the probe-side failure last Warn'd — the PROBE-ERR line
	// logs once on state-change (entering probe_error, or the class
	// pair changing), and a recovery line logs once when the cycle
	// stops being all-probe-side. A multi-hour credential outage
	// logs a handful of lines, not one per cycle. Deliberately
	// RAM-only — it dedupes LOG lines, carries no verdict state, and
	// a restart re-logging one line is correct behavior.
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

// pruneStaleBackends drops in-memory probe state, the persisted
// apibe-* counter files (when dir != "") and every per-backend
// metric series for names no longer present in discovery — a
// backend retired from api-local-lb would otherwise pin its
// p.states entry, its on-disk wedge streaks and its label values
// on the registry forever. Only runs when discovery returned rows
// — never on discover failure or an empty backend list.
func (p *Prober) pruneStaleBackends(dir string, backends []backend) {
	live := make(map[string]bool, len(backends))
	for _, b := range backends {
		live[b.Name] = true
	}
	for name := range p.states {
		if live[name] {
			continue
		}
		delete(p.states, name)
		if dir != "" {
			// The RAM prune owns the disk prune — both key on the
			// same backend name, and a departed backend's streak
			// must not resume if its name is ever reused.
			p.removeStateFiles(dir, name)
		}
		p.rvGap.DeleteLabelValues(name)
		p.enabled.DeleteLabelValues(name)
		logger().Info("apiprober: backend left HAProxy discovery — pruned "+
			"probe state, state files and metric series",
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
// Best-effort: a write failure is logged, never fatal. The
// read-compare gate skips the full tmp+fsync+rename+dir-fsync when
// the content is unchanged — a healthy backend writes the same
// "0\n"-ish value every 30s (the collect_nebula.go cert-days
// pattern).
func (p *Prober) writeGapFile(dir string, b backend, gap int64) {
	f := dir + "/apibe-gap-" + dashedIP(b.Addr)
	content := strconv.FormatInt(gap, 10) + "\n"
	if cur, err := os.ReadFile(f); err == nil && string(cur) == content {
		return
	}
	// NoSync: the gap file is rewritten every cycle and re-read by
	// prom_emit — durability buys nothing a crash couldn't recover
	// next cycle, while the fsync pair fired every 30s per backend.
	if err := fsx.WriteFileAtomicNoSync(f, content); err != nil {
		logger().Warn("watchdog gap file write failed",
			"file", f, "backend", b.Name, "error", err,
		)
	}
}

// staleLatched reports whether b's stale latch file exists — a
// stat-only probe the healthy path uses to know whether the ok
// streak still has a latch to recover from (vs the tmp+rename+fsync
// a counter-file rewrite costs every cycle it keeps counting).
func (p *Prober) staleLatched(dir string, b backend) bool {
	_, err := os.Stat(dir + "/" + latchdefs.LatchFilePrefix +
		latchdefs.LatchAPIServerBackendStalePrefix + dashedIP(b.Addr))
	return err == nil
}

// latchStale creates state-apiserver-backend-stale-<ip> — state_enter
// semantics: create only if absent, content = current epoch. An
// existing latch gets its mtime refreshed (BUG-H6) — the janitor
// reaps state-* files older than 24h and a backend wedged for days
// must not lose its latch mid-episode (the prober has no clock seam;
// the same time.Now the epoch content carries keys the touch).
func (p *Prober) latchStale(dir string, b backend) {
	f := dir + "/" + latchdefs.LatchFilePrefix +
		latchdefs.LatchAPIServerBackendStalePrefix + dashedIP(b.Addr)
	if fi, err := os.Stat(f); err == nil {
		now := p.cfg.Clock.Now()
		// Touch only once the mtime ages past LatchTouchMinInterval —
		// the janitor reaps at 24h; per-cycle utimensat was needless.
		if cerr := fsx.TouchIfDue(f, fi, now,
			latchdefs.LatchTouchMinInterval); cerr != nil {
			logger().Debug("watchdog stale latch touch failed",
				"file", f, "backend", b.Name, "error", cerr)
		}
		return
	}
	if err := fsx.WriteFileAtomicBytes(f,
		[]byte(strconv.FormatInt(p.cfg.Clock.Now().Unix(), 10)+"\n")); err != nil {
		logger().Warn("watchdog stale latch write failed",
			"file", f, "backend", b.Name, "error", err,
		)
	}
}

// clearStale removes the stale latch — state_exit semantics, called
// only on a fully-fresh cycle (hysteresis: inconclusive cycles keep
// whatever exists). not-exist is ignored.
func (p *Prober) clearStale(dir string, b backend) {
	f := dir + "/" + latchdefs.LatchFilePrefix +
		latchdefs.LatchAPIServerBackendStalePrefix + dashedIP(b.Addr)
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
		case strings.HasPrefix(name, latchdefs.LatchFilePrefix+
			latchdefs.LatchAPIServerBackendStalePrefix):
			suffix = strings.TrimPrefix(name, latchdefs.LatchFilePrefix+
				latchdefs.LatchAPIServerBackendStalePrefix)
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

// --- per-backend counter persistence (the restart witness) ---
// backendState's $STATE_DIR parity: the shell kept qfail-/frozen-/
// fail-/ok-/drained- files per backend under $STATE_DIR so a script
// re-run resumed the streak it died on; the agent mirrors the same
// family to apibe-<counter>-<name> files so an AGENT restart does
// the same — without it a restart re-armed every wedge streak from
// zero and forgot which backends it had drained (HAProxy's MAINT is
// the only surviving memory, and maint() cannot tell our drain from
// a deliberate manual one).
//
// Keying is by backend NAME — the p.states key — not the dashed-IP
// suffix the cross-process files use: VIPs (api_*_lb) and
// static-only backends have no meaningful probe Addr to dash, and
// the name is the identity every verdict path already uses. The
// family is internal-only — no other process reads it (the janitor
// reaps only state-*), and the cross-process contract is unchanged:
// state-apiserver-backend-stale-<ip> + apibe-gap-<ip>.

// apibeStatePrefixes is the persisted family per backend — suffix =
// stateFileKey(name). drained is a marker (presence = drained),
// prevcache an int64 baseline, the rest int counters.
var apibeStatePrefixes = []string{
	"apibe-qfail-", "apibe-frozen-", "apibe-fail-", "apibe-ok-",
	"apibe-drained-", "apibe-prevcache-",
}

// stateFileKey sanitizes a backend name for an apibe-* filename —
// any char outside [A-Za-z0-9._-] maps to '-'. Discovered svnames
// and API_BACKENDS names are already filename-safe; the map is the
// belt for a conf-carried name that is not.
func stateFileKey(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z',
			'0' <= r && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '-'
	}, name)
}

// loadState folds the persisted apibe-* files into st — the restart
// half of the witness. Runs at most once per backend per process
// (the caller gates on st.loaded): RAM is authoritative for the
// rest of the run. Absent/garbage reads collapse to zero — the
// hoststate rate_ok "garbage → 0" parity — so a hand-edited or torn
// file loses a streak rather than inventing one.
func (p *Prober) loadState(dir, name string, st *backendState) {
	if st.loaded || dir == "" {
		return
	}
	key := stateFileKey(name)
	st.qfail = stateCounter(dir + "/apibe-qfail-" + key)
	st.frozen = stateCounter(dir + "/apibe-frozen-" + key)
	st.fail = stateCounter(dir + "/apibe-fail-" + key)
	st.ok = stateCounter(dir + "/apibe-ok-" + key)
	if v, ok := readStateInt(dir + "/apibe-prevcache-" + key); ok {
		// Without the persisted baseline the first post-restart
		// cycle runs hasPrev=false — the frozen else-branch would
		// zero a streak that was mid-accumulation on disk.
		st.prevCache, st.hasPrev = v, true
	}
	// The drained marker is presence-only — content (the epoch the
	// drain latched) is informational.
	if _, err := os.Stat(dir + "/apibe-drained-" + key); err == nil {
		st.drained = true
	}
	st.loaded = true
}

// saveState mirrors one backend's counters to its apibe-* files.
// Zero counters DELETE the file rather than writing "0" — absent
// reads as zero on load, so a healthy run leaves no litter. The
// drained marker mirrors st.drained (create-if-absent keeps the
// epoch the drain first latched — state_enter parity); prevcache
// exists only while hasPrev holds. Best-effort like writeGapFile —
// a failure is Warn'd, never fatal.
func (p *Prober) saveState(dir, name string, st *backendState) {
	key := stateFileKey(name)
	p.writeStateCounter(dir+"/apibe-qfail-"+key, int64(st.qfail))
	p.writeStateCounter(dir+"/apibe-frozen-"+key, int64(st.frozen))
	p.writeStateCounter(dir+"/apibe-fail-"+key, int64(st.fail))
	p.writeStateCounter(dir+"/apibe-ok-"+key, int64(st.ok))
	prev := dir + "/apibe-prevcache-" + key
	// The baseline only earns a restart witness while a verdict is
	// in flight — it exists to resume a frozen/gap/fail streak or a
	// drain recovery. A fully-healthy backend's rv_cache advances
	// every cycle, so persisting it was a tmp+rename+fsync every
	// 30s for nothing (the "healthy run leaves no litter" rule).
	if st.hasPrev && (st.qfail > 0 || st.frozen > 0 || st.fail > 0 ||
		st.ok > 0 || st.drained) {
		p.writeStateFile(prev, strconv.FormatInt(st.prevCache, 10))
	} else {
		p.removeStateFile(prev)
	}
	drained := dir + "/apibe-drained-" + key
	if st.drained {
		if _, err := os.Stat(drained); err != nil {
			p.writeStateFile(drained,
				strconv.FormatInt(p.cfg.Clock.Now().Unix(), 10))
		}
	} else {
		p.removeStateFile(drained)
	}
}

// flushStates mirrors every in-memory backend state to its apibe-*
// files — deferred at cycle end so the mid-loop ctx.Err() early
// return and a shutdown still persist the partial round's counters.
func (p *Prober) flushStates(dir string) {
	for name, st := range p.states {
		p.saveState(dir, name, st)
	}
}

// removeStateFiles deletes a departed backend's whole apibe-*
// family — called by pruneStaleBackends, which owns both halves of
// the per-backend state under the same name key.
func (p *Prober) removeStateFiles(dir, name string) {
	key := stateFileKey(name)
	for _, prefix := range apibeStatePrefixes {
		p.removeStateFile(dir + "/" + prefix + key)
	}
}

// stateCounter reads an int counter file — absent/garbage → 0.
func stateCounter(path string) int {
	v, _ := readStateInt(path)
	return int(v)
}

// readStateInt reads an int64 file, reporting (value, parsed) —
// callers that key on presence use the bool (prevcache's hasPrev);
// counters ignore it.
func readStateInt(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// writeStateFile mirrors one apibe-* file through the atomic
// tmp+rename contract — best-effort: a failed write only costs a
// restart some streak context.
func (p *Prober) writeStateFile(path, content string) {
	if err := fsx.WriteFileAtomicBytes(path,
		[]byte(content+"\n")); err != nil {
		logger().Warn("apiprober state file write failed",
			"file", path, "error", err,
		)
	}
}

// writeStateCounter writes a counter file, or deletes it at zero —
// absent IS zero on the read side, so a "0" file is pure litter.
func (p *Prober) writeStateCounter(path string, n int64) {
	if n <= 0 {
		p.removeStateFile(path)
		return
	}
	p.writeStateFile(path, strconv.FormatInt(n, 10))
}

// removeStateFile deletes one apibe-* file — not-exist is fine.
func (p *Prober) removeStateFile(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logger().Warn("apiprober state file remove failed",
			"file", path, "error", err,
		)
	}
}
