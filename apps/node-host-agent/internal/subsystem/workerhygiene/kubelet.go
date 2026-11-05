package workerhygiene

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// countMatchingLines is grep -cE parity: lines matching re.
// strings.Cut iterates in place — no giant []string allocation on
// a multi-MiB journal snapshot.
func countMatchingLines(re *regexp.Regexp, s string) int {
	n := 0
	for rest := s; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if re.MatchString(line) {
			n++
		}
	}
	return n
}

// dashedHost maps "ip[:port]" to the watchdog file suffix ip-dashed —
// same transform as apiprober's dashedIP (state-apiserver-backend-
// stale-<dashed> keying).
func dashedHost(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		host = addr[:i]
	}
	return strings.ReplaceAll(host, ".", "-")
}

// probeHTTPSeries runs up to `attempts` GET probes `gap` apart —
// the shell's curl retry loops (a single blip must not trigger a
// restart). Returns nil on the first success.
func (h *Hygiene) probeHTTPSeries(ctx context.Context, url string,
	attempts int, timeout, gap time.Duration) error {
	var last error
	for i := 0; i < attempts; i++ {
		last = h.cfg.probeHTTP(ctx, url, timeout)
		if last == nil {
			return nil
		}
		if i+1 < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(gap):
			}
		}
	}
	return last
}

// kubelet10250Alive runs the kubelet :10250 /healthz liveness series
// — the shell's `curl -ks` retry loop. ANY HTTP response proves the
// listener is alive; only a transport error/timeout counts as down.
// A 401/403 is kubelet answering an auth denial, NOT a dead listener
// — probing anonymously read that as "down" → kubelet-10250-down →
// k0sworker restarts spent on a healthy kubelet (same bug class the
// syncloop probe fixed by authenticating + treating unauth answers
// as non-verdicts). The SA bearer from KubeletTokenPath rides along
// so clusters requiring auth return the real healthz verdict; a
// missing token just falls back to anonymous, whose 401 still counts
// as alive.
func (h *Hygiene) kubelet10250Alive(ctx context.Context) bool {
	bearer := h.kubeletBearer()
	for i := 0; i < probeAttempts; i++ {
		if _, err := h.cfg.probeHTTPStatus(ctx,
			h.cfg.KubeletHealthzURL, bearer, probeTimeout); err == nil {
			return true
		}
		if i+1 < probeAttempts {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(h.cfg.ProbeGap):
			}
		}
	}
	return false
}

// podDirCount counts kubelet pod dirs — the shell's
// `find $KUBELET_PODS_DIR -mindepth 1 -maxdepth 1 -type d | wc -l`.
// ok=false means the dir is unreadable (treated like missing).
func (h *Hygiene) podDirCount() (n int, ok bool) {
	entries, err := os.ReadDir(h.cfg.KubeletPodsDir)
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n, true
}

// taskRecordCount counts containerd task records — `ctr tasks ls |
// wc -l` parity for the phantom-pods signal: every task dir under the
// runtime + sandbox roots is a record, RUNNING or STOPPED alike (the
// shell counted output lines, never filtered on task state). A
// drained/evicted node holding stopped task dirs is NOT phantom —
// counting only live init pids would false-positive a k0sworker
// restart every MinRestartInterval.
func (h *Hygiene) taskRecordCount() int {
	n := 0
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				n++
			}
		}
	}
	return n
}

// k0sWorkerSettled gates k0sworker restarts: the unit must have been
// continuously active for >=180s — restarting a kubelet that is still
// re-listing its pods turns a settle blip into a restart loop.
// nil Systemd (unwired/tests) can't answer → settled.
func (h *Hygiene) k0sWorkerSettled(ctx context.Context) bool {
	if h.cfg.Systemd == nil {
		return true
	}
	age, err := h.cfg.Systemd.ActiveAge(ctx, "k0sworker.service")
	return err == nil && age >= k0sWorkerSettle
}

// restartK0sWorker wraps Systemd.Restart — a nil client can't act
// (unwired agent) and reports so the action is logged not counted.
func (h *Hygiene) restartK0sWorker(ctx context.Context) error {
	if h.cfg.Systemd == nil {
		return fmt.Errorf("no systemd client wired")
	}
	return h.cfg.Systemd.Restart(ctx, "k0sworker.service")
}

// --- Check: kubelet-stall (05-kubelet-stall.sh) ---

// stallCheck detects a zombie kubelet: informer-zombie journal
// spam, phantom pods (pod dirs but zero task records), or a dead
// :10250 listener. 2 consecutive cycles → latch kubelet-runtime-stall
// + restart k0sworker through the shared last-restart budget, gated
// on overload / API reachability / settle. The streak stays on
// Hygiene (stallFails) — pre-Check tests poke it directly.
type stallCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *stallCheck) Name() string { return checkStall }

// Run executes one kubelet-stall round.
func (c *stallCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkStall, "gated").Inc()
		return
	}
	reason := ""
	if hits := countMatchingLines(stallJournalRe, e.journalOnce()); hits > journalHitsThresh {
		reason = fmt.Sprintf("informer-zombie hits=%d/10min", hits)
	}
	if reason == "" {
		if poddirs, ok := c.h.podDirCount(); ok && poddirs >= poddirThreshold {
			if _, err := os.ReadDir(c.h.cfg.CtrTaskRoot); err != nil {
				reason = fmt.Sprintf("phantom-pods poddirs=%d ctr=unreachable", poddirs)
			} else if c.h.taskRecordCount() == 0 {
				reason = fmt.Sprintf("phantom-pods poddirs=%d tasks=0", poddirs)
			}
		}
	}
	if reason == "" {
		// kubelet-10250-down: the listener may take 30-60s after a
		// k0sworker restart — all 3 probes must fail (curl -ks parity:
		// ANY HTTP response, even 401/403, means the listener is
		// alive).
		if !c.h.kubelet10250Alive(ctx) {
			reason = "kubelet-10250-down"
		}
	}
	if reason == "" {
		c.h.stallFails = 0
		c.h.state.Exit("kubelet-runtime-stall", nil)
		c.h.cycles.WithLabelValues(checkStall, "ok").Inc()
		return
	}
	c.h.stallFails++
	if c.h.stallFails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s (check %d/%d)",
			reason, c.h.stallFails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkStall, "ok").Inc()
		return
	}
	overloaded := c.h.state.Exists("node-overloaded")
	if strings.HasPrefix(reason, "phantom-pods") || strings.HasPrefix(reason, "kubelet-10250-down") {
		if !overloaded {
			c.h.state.Enter("kubelet-runtime-stall", reason)
		} else if !c.h.state.Exists("kubelet-runtime-stall") {
			// Wedge under CPU starvation is a symptom, not a dead
			// node — latching would kick NHC→SNR and dump 100% of
			// load onto the survivors (amplifier). Log-only.
			c.h.state.AppendLog(fmt.Sprintf("runtime-stall-suppressed-overloaded - %s", reason))
		}
	} else {
		c.h.state.Exit("kubelet-runtime-stall", nil)
	}
	switch {
	case overloaded:
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - node overloaded, skip restart k0sworker", reason))
	case !e.apiOK:
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - API unreachable (isolated?), skip restart k0sworker", reason))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - k0sworker not settled (<180s), skip restart", reason))
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - in restart cooldown (<30m), skip", reason))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf("ACTION: restarting k0sworker - %s (persisted %dx)",
			reason, c.h.stallFails))
		c.h.stallFails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkStall, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkStall, "ok").Inc()
}

// --- Check: kubelet-watch-wedge (06-kubelet-watch-wedge.sh) ---

// watchWedgeCheck detects a wedged kubelet pod-watch stream: pods
// assigned to this node (not Terminating, not terminal, older than
// KubeletWatchMinAge) whose kubelet pod dir was never created.
// Journal spam is early-warning only. 2 consecutive cycles → latch
// kubelet-watch-wedge + restart k0sworker — unless EVERY apiserver
// backend is stale (upstream wedge: the missing pods are a phantom of
// stale LIST data, restarting kubelet is useless churn). fails is the
// consecutive unseen-pods streak (ex-Hygiene.watchFails).
type watchWedgeCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *watchWedgeCheck) Name() string { return checkWatch }

// Run executes one watch-wedge round.
func (c *watchWedgeCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkWatch, "gated").Inc()
		return
	}
	if spam := countMatchingLines(watchJournalRe, e.journalOnce()); spam > journalHitsThresh {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge early-warn spam=%d/10min (not-registered/no-relationship)", spam))
	}
	if !e.apiOK {
		// Inconclusive — keep counters/latch exactly like the shell
		// (a flapping API must not clear wedge evidence). Only log
		// when there is something worth keeping.
		if c.h.state.Exists("kubelet-watch-wedge") || c.fails > 0 {
			c.h.state.AppendLog("suspect: kubelet-watch-wedge pods query fail — inconclusive, keeping state")
		}
		c.h.cycles.WithLabelValues(checkWatch, "abort").Inc()
		return
	}
	// Stat the pods ROOT once before the per-pod sweep: with the dir
	// itself unreadable/vanished every per-pod stat fails and ALL
	// assigned pods count "missing" → false wedge latch + a k0sworker
	// restart spent on a filesystem blip. The IsDir half matters just
	// as much as the error half: a regular FILE at the path stats
	// cleanly but every per-pod join then fails ENOTDIR — the same
	// false wedge via a different syscall. Inconclusive — keep
	// counters/latch exactly like the !apiOK path.
	st, err := os.Stat(c.h.cfg.KubeletPodsDir)
	if err != nil || !st.IsDir() {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet pods dir %s unstatable or not a directory (isdir=%v, err=%v) — watch-wedge inconclusive, keeping state",
			c.h.cfg.KubeletPodsDir, err == nil && st.IsDir(), err))
		c.h.cycles.WithLabelValues(checkWatch, "abort").Inc()
		return
	}
	now := c.h.cfg.nowFn()
	missing := 0
	for i := range e.pods {
		p := &e.pods[i]
		if p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		ct := p.CreationTimestamp.Time
		if ct.IsZero() || now.Sub(ct) < c.h.cfg.KubeletWatchMinAge {
			continue
		}
		if st, err := os.Stat(filepath.Join(c.h.cfg.KubeletPodsDir,
			string(p.UID))); err != nil || !st.IsDir() {
			missing++
		}
	}
	if missing == 0 {
		c.fails = 0
		c.h.state.Exit("kubelet-watch-wedge", nil)
		c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge %d pod(s) assigned but no pod dir on node (check %d/%d)",
			missing, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
		return
	}
	c.h.state.Enter("kubelet-watch-wedge", fmt.Sprintf("unseen-pods=%d", missing))
	// Upstream gate: EVERY apiserver backend stale → the unseen pods
	// are stale-LIST fallout, not a kubelet wedge (sig14 latches the
	// state-apiserver-backend-stale-<ip> files).
	if len(c.h.cfg.APIBackends) > 0 {
		nstale := 0
		for _, be := range c.h.cfg.APIBackends {
			if c.h.state.Exists("apiserver-backend-stale-" + dashedHost(be)) {
				nstale++
			}
		}
		if nstale == len(c.h.cfg.APIBackends) {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: kubelet-watch-wedge unseen=%d but %d/%d api backend stale — upstream wedge, skip restart k0sworker",
				missing, nstale, len(c.h.cfg.APIBackends)))
			c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
			return
		}
	}
	switch {
	case c.h.state.Exists("node-overloaded"):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - node overloaded, skip restart k0sworker", missing))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - k0sworker not settled (<180s), skip restart", missing))
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - in restart cooldown (<30m), skip", missing))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-watch-wedge unseen-pods=%d (persisted %dx)",
			missing, c.fails))
		c.fails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkWatch, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
}

// --- Check: ctr-tasks (31-ctr-tasks.sh) ---

// runKubeletFeeder is the T15 feeder's forever loop — returns only
// when ctx is cancelled. The tick self-gates per round; the "start"
// line is logged on each activation transition inside the tick, not
// here — the goroutine also runs on nodes where the feeder never
// activates.
func (h *Hygiene) runKubeletFeeder(ctx context.Context) {
	cycle.Every("kubelet-feeder", h.cfg.KubeletWdInterval,
		h.kubeletFeedTick).Run(ctx)
}

// kubeletFeederActive reports whether the feeder should probe this
// node — the shell install gate: the unit ran only on hosts listed in
// systemd_watchdog_hosts (KubeletWatchdogHosts); in-agent the check
// ALSO passes by default on any worker node (k0sworker.service
// present — the pilot graduated fleet-wide). WD_SIG_KUBELET_WATCHDOG
// =off is the per-module kill switch, honoured live via WatchdogSrc.
func (h *Hygiene) kubeletFeederActive() bool {
	if wd := h.feederWatchdogConf(); wd != nil && !wd.SignalEnabled(checkKubeletWd) {
		return false
	}
	for _, name := range h.cfg.KubeletWatchdogHosts {
		if name == h.cfg.NodeName {
			return true
		}
	}
	_, err := os.Stat(h.cfg.K0sWorkerUnitFile)
	return err == nil
}

// feederWatchdogConf returns the freshest parsed node-watchdog.conf
// WITHOUT mutating cfg — Cycle refreshes cfg.Watchdog itself; the
// feeder goroutine must never write cfg fields (data race).
func (h *Hygiene) feederWatchdogConf() *watchdogconf.Config {
	if h.cfg.WatchdogSrc != nil {
		return h.cfg.WatchdogSrc.Get()
	}
	// Without a reloader cfg.Watchdog is immutable — Cycle's refresh
	// block is guarded by WatchdogSrc != nil too.
	return h.cfg.Watchdog
}

// kubeletFeedTick is one feeder round: probe :10248, count fails, run
// the remediate gates at MaxFail — k0s-kubelet-watchdog.sh's loop
// body minus the sd_notify feed (no watchdog unit exists in-agent).
func (h *Hygiene) kubeletFeedTick(ctx context.Context) {
	active := h.kubeletFeederActive()
	if active && !h.kubeletFeederWasActive {
		// false→true activation (first active tick, node re-added to
		// systemd_watchdog_hosts, unit file reinstalled, WD_SIG
		// lifted) — a partial fail-streak from before the gap is
		// stale evidence and must not count toward a restart.
		h.state.AppendLog(fmt.Sprintf(
			"kubelet-feeder: start interval=%ds maxfail=%d url=%s",
			int(h.cfg.KubeletWdInterval.Seconds()), h.cfg.KubeletWdMaxFail,
			h.cfg.KubeletWdProbeURL))
		if h.kubeletWdFails > 0 {
			h.state.AppendLog(fmt.Sprintf(
				"kubelet-feeder: re-activated — dropping %d stale fails", h.kubeletWdFails))
		}
		h.kubeletWdFails = 0
	}
	h.kubeletFeederWasActive = active
	if !active {
		return
	}
	if h.cfg.probeBodyOK(ctx, h.cfg.KubeletWdProbeURL, kubeletWdProbeTimeout) {
		if h.kubeletWdFails > 0 {
			h.state.AppendLog(fmt.Sprintf(
				"kubelet-feeder: probe OK again after %d fail", h.kubeletWdFails))
		}
		h.kubeletWdFails = 0
		h.state.Exit("kubelet-healthz-down", nil)
		return
	}
	// PartOf=k0sworker.service parity: the shell feeder unit stood
	// down with k0sworker — an intentionally inactive worker must not
	// accumulate fails toward a restart it doesn't want, and must not
	// keep a healthz-down latch that escalates a deliberate stop into
	// an NHC→SNR reboot.
	if h.cfg.Systemd != nil {
		active, err := h.cfg.Systemd.Active(ctx, "k0sworker.service")
		if err != nil {
			// Fail closed: the gate can't be evaluated — freeze
			// this tick entirely. Accumulating fails could escalate
			// to remediation on an unverifiable worker state, while
			// resetting them would discard real evidence.
			logger().Warn("kubelet-feeder: k0sworker is-active probe "+
				"failed — skipping this tick (fail closed)",
				"unit", "k0sworker.service", "error", err)
			return
		}
		if !active {
			if h.kubeletWdFails > 0 {
				h.state.AppendLog("kubelet-feeder: k0sworker not active — fails reset (PartOf parity)")
			}
			h.kubeletWdFails = 0
			h.state.Exit("kubelet-healthz-down", nil)
			return
		}
	}
	h.kubeletWdFails++
	h.state.AppendLog(fmt.Sprintf("kubelet-feeder: probe fail %d/%d",
		h.kubeletWdFails, h.cfg.KubeletWdMaxFail))
	if h.kubeletWdFails < h.cfg.KubeletWdMaxFail {
		return
	}
	h.state.AppendLog(fmt.Sprintf(
		"kubelet-feeder: %d consecutive fails (~%ds) — running remediation gates",
		h.kubeletWdFails,
		int(h.cfg.KubeletWdInterval.Seconds())*h.cfg.KubeletWdMaxFail))
	h.runKubeletRemediate(ctx)
	// Re-arm like the shell's exit-1 → unit fail → OnFailure →
	// Restart=always round: the remediate pass ENDS this fails run
	// whatever the gates decided.
	h.kubeletWdFails = 0
}

// runKubeletRemediate is the ordered-gate port of
// k0sworker-remediate.sh — a probe failure does NOT prove the kubelet
// is dead (the probe may just be timing out under steal); every gate
// is a chance to stop before the shared last-restart budget is spent.
func (h *Hygiene) runKubeletRemediate(ctx context.Context) {
	h.actions.WithLabelValues(checkKubeletWd, "remediate").Inc()
	h.state.AppendLog("kubelet-remediate: healthz :10248 down ~60s — running ordered gates before k0sworker restart")

	// G0 re-probe — the shell's Gate 1: probe :10248 twice ~3s apart
	// before ANYTHING else. Four failed ticks do not prove a dead
	// kubelet — under CPU steal the probes themselves time out, and
	// the ~60s streak may already be over. One "ok" → self-correct
	// (drop the fail streak and any escalation latch), never spend a
	// restart on a healthy kubelet.
	for i := 1; i <= 2; i++ {
		if h.cfg.probeBodyOK(ctx, h.cfg.KubeletWdProbeURL, kubeletWdProbeTimeout) {
			h.state.AppendLog(fmt.Sprintf(
				"kubelet-remediate: SKIP(G0-reprobe) :10248 answered 'ok' on re-probe %d — false alarm (steal blip), self-correcting", i))
			h.kubeletWdFails = 0
			h.state.Exit("kubelet-healthz-down", nil)
			return
		}
		if i < 2 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(h.cfg.KubeletWdReprobeGap):
			}
		}
	}
	h.state.AppendLog("kubelet-remediate: G0 :10248 still dead after 2 re-probes — continuing ordered gates")

	// G1 uptime (WD_REQUIRES: uptime) — a node <20m up is still
	// bringing kubelet online; a restart inside the window only churns.
	if up, err := h.proc.UptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.state.AppendLog(fmt.Sprintf(
			"kubelet-remediate: SKIP(G1-uptime) uptime %.0fs < %ds", up, minUptimeSeconds))
		return
	}

	// G2 settle — k0sworker ActiveEnterTimestampMonotonic younger than
	// the 180s settle window: the kubelet from the previous restart may
	// still be initialising; spending the budget now just resets that
	// init cycle. An unreadable timestamp also skips (never restart
	// blind).
	if !h.k0sWorkerSettled(ctx) {
		h.state.AppendLog("kubelet-remediate: SKIP(G2-settle) k0sworker active <180s or timestamp unreadable")
		return
	}

	// G3 overload — a kubelet wedge under CPU starvation is a
	// symptom, not a dead kubelet; restarting dumps its load onto the
	// surviving nodes (amplifier).
	if h.state.Exists("node-overloaded") {
		h.state.AppendLog("kubelet-remediate: SKIP(G3-overload) state-node-overloaded latched")
		return
	}

	// G4 apiserver — a node that reaches NO API backend is isolated;
	// restarting kubelet only adds a NotReady blip + resync churn.
	if !h.anyAPIBackendLive(ctx) {
		h.state.AppendLog("kubelet-remediate: SKIP(G4-apiserver) no API backend answers /livez — node isolated")
		return
	}

	// G5 rate-limit — the last-restart budget is SHARED with every
	// other k0sworker restart source (30m), including the Cycle checks
	// running on their own goroutine — the check+spend is atomic
	// (rateTrySpend) or a stall/watch restart could pass the same
	// window and double-restart. Exhausted → escalate to the NHC→SNR
	// reboot path via the latch instead of piling on.
	if !h.state.RateTrySpend("last-restart", h.cfg.MinRestartInterval) {
		h.state.Enter("kubelet-healthz-down", "restart-budget-exhausted")
		h.state.AppendLog("kubelet-remediate: SKIP(G5-ratelimit) k0sworker restart <30m ago — " +
			"state-kubelet-healthz-down latched (NHC→SNR escalation)")
		return
	}

	// G6 act — the budget was already spent atomically above (shell
	// parity: a hung/failed restart still consumed it). reset-failed
	// first so a stale failed state can't wedge the unit's next start.
	h.state.AppendLog(fmt.Sprintf(
		"ACTION: restarting k0sworker (reason=systemd-watchdog-kubelet-healthz-60s fails=%d)",
		h.cfg.KubeletWdMaxFail))
	h.resetFailedK0sWorker(ctx)
	if err := h.restartK0sWorker(ctx); err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"kubelet-remediate: G6 restart k0sworker FAIL: %v (budget spent)", err))
		return
	}
	h.state.AppendLog("kubelet-remediate: G6 k0sworker restarted")
	h.actions.WithLabelValues(checkKubeletWd, "restart").Inc()
}

// anyAPIBackendLive is the G4 probe — the shell TCP-checked the
// apiserver endpoint (API_PROBE_HOSTPORT/kubelet.conf) before
// declaring the node isolated; the agent GETs /livez on every
// configured API backend (API_BACKENDS, ports preserved) and counts
// ANY HTTP response as reachable (curl -sk parity — even a 500 means
// the listener is alive). With no backends configured it falls back
// to the worker-local api-local-lb listener (APIFallbackURL).
func (h *Hygiene) anyAPIBackendLive(ctx context.Context) bool {
	var urls []string
	if wd := h.feederWatchdogConf(); wd != nil {
		for _, b := range wd.APIBackends {
			if b.Addr != "" {
				urls = append(urls,
					"https://"+withDefaultAPIPort(b.Addr)+"/livez")
			}
		}
	}
	if len(urls) == 0 && h.cfg.WatchdogSrc == nil {
		// No reloader → cfg.APIBackends is immutable (Cycle refreshes
		// it from the conf only when a reloader exists).
		for _, a := range h.cfg.APIBackends {
			urls = append(urls, "https://"+withDefaultAPIPort(a)+"/livez")
		}
	}
	if len(urls) == 0 {
		urls = []string{h.cfg.APIFallbackURL}
	}
	for _, url := range urls {
		// probeHTTPStatus, not probeHTTP: the verdict is liveness,
		// so ANY HTTP code — even 401/403/500 — proves the listener
		// answered (curl -sk parity; a 2xx-only read made an
		// auth-refusing or LB-degraded endpoint look "unreachable"
		// and falsely gated remediation as isolated).
		if _, err := h.cfg.probeHTTPStatus(ctx, url, "",
			apiLivezProbeTimeout); err == nil {
			return true
		}
	}
	return false
}

// withDefaultAPIPort appends the apiserver default port to a bare-IP
// backend entry — API_BACKENDS is "ip:port" but bare-IP entries occur
// (APIBackendIPs strips ports for the stale-latch key).
func withDefaultAPIPort(addr string) string {
	// An EMPTY port parses cleanly ("1.2.3.4:" → host ok, port "")
	// but builds a malformed probe URL ("https://1.2.3.4:/livez")
	// that fails every GET silently → node reads isolated forever.
	// Treat it as "port missing" like a bare IP.
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return addr
	}
	addr = strings.TrimSuffix(addr, ":")
	if strings.LastIndexByte(addr, ':') < 0 ||
		(strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]")) {
		return addr + ":6443"
	}
	return addr
}

// resetFailedK0sWorker mirrors `systemctl reset-failed k0sworker` —
// clears a lingering failed state so the following restart is a clean
// start, not a retry of a queued failed job. Best-effort: an error is
// logged, never fatal; a nil Systemd client (unwired agent/tests) is
// a no-op.
func (h *Hygiene) resetFailedK0sWorker(ctx context.Context) {
	if h.cfg.Systemd == nil {
		return
	}
	if out, err := h.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "k0sworker.service"); err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"kubelet-remediate: reset-failed k0sworker failed: %v (%s)",
			err, strings.TrimSpace(out)))
	}
}

// --- Check: kubelet syncloop / containerd socket (A4) ---
// 05's :10250 /healthz probe can stay green through a PLEG freeze —
// kubelet exposes /healthz/syncloop specifically for the sync loop
// (returns 500 the moment PLEG dies). The containerd unix socket is
// the other half: a hung containerd wedges PLEG while every HTTP
// endpoint still answers. Both latches now self-heal (BUG-H4): at
// ConsecNeeded fails they run the shared k0sworker restart gates
// (overload / settle / last-restart budget) instead of waiting for
// 05/T15 to notice.

// syncloopCheck is the A4 PLEG probe as a Check; it owns the
// consecutive-fail streak and the unauth-logged flag (ex-Hygiene
// .syncloopFails/.syncloopUnauth).
type syncloopCheck struct {
	h      *Hygiene
	fails  int
	unauth bool // last probe was 401/403 — log the streak once
}

// Name returns the check label / WD_SIG key.
func (c *syncloopCheck) Name() string { return checkSyncloop }

// Run executes one kubelet-syncloop round.
func (c *syncloopCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkSyncloop, "gated").Inc()
		return
	}
	var lastErr error
	alive := false
	unauth := false
	// The bearer token is re-read every cycle — the file is small
	// and bound SA tokens rotate.
	bearer := c.h.kubeletBearer()
	for i := 0; i < probeAttempts; i++ {
		code, err := c.h.cfg.probeHTTPStatus(ctx,
			c.h.cfg.KubeletSyncloopURL, bearer, probeTimeout)
		if err == nil {
			switch {
			case code == http.StatusOK:
				alive = true
			case code == http.StatusUnauthorized || code == http.StatusForbidden:
				// Kubelet answered but won't divulge the verdict —
				// retrying the same credentials won't help.
				unauth = true
			default:
				lastErr = fmt.Errorf("syncloop status %d", code)
			}
		} else {
			lastErr = err
		}
		if alive || unauth {
			break
		}
		if i+1 < probeAttempts {
			select {
			case <-ctx.Done():
				c.h.cycles.WithLabelValues(checkSyncloop, "abort").Inc()
				return
			case <-time.After(c.h.cfg.ProbeGap):
			}
		}
	}
	if unauth {
		// The verdict is unknowable without working credentials —
		// inconclusive like the other keep-state paths, NOT a down
		// signal. Logged once per unauth streak so a permanently
		// unauthenticated deployment doesn't spam every cycle.
		if !c.unauth {
			c.h.state.AppendLog("suspect: kubelet-syncloop-down probe unauthorized " +
				"(401/403 — token missing or RBAC nonResourceURL /healthz/* not " +
				"granted) — inconclusive, keeping state")
			c.unauth = true
		}
		c.h.cycles.WithLabelValues(checkSyncloop, "inconclusive").Inc()
		return
	}
	c.unauth = false
	if alive {
		c.fails = 0
		c.h.state.Exit("kubelet-syncloop-down", nil)
		c.h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down /healthz/syncloop fail (PLEG?) err=%v (check %d/%d)",
			lastErr, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
		return
	}
	// BUG-H4: a frozen PLEG is a kubelet stall the 05 probe can't
	// see — confirmed consecutive fails now self-heal through the
	// shared k0sworker restart gates (overload / settle /
	// last-restart budget), checkKubeletStall parity.
	overloaded := c.h.state.Exists("node-overloaded")
	if !overloaded {
		c.h.state.Enter("kubelet-syncloop-down",
			fmt.Sprintf("pleg-frozen last_err=%v", lastErr))
	} else if !c.h.state.Exists("kubelet-syncloop-down") {
		// A stall under CPU starvation is a symptom — latching
		// would escalate to NHC→SNR and dump 100% of the load
		// onto the survivors (amplifier). Log-only.
		c.h.state.AppendLog(fmt.Sprintf(
			"kubelet-syncloop-down suppressed-overloaded - pleg-frozen last_err=%v", lastErr))
	}
	switch {
	case overloaded:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-syncloop-down - node overloaded, skip restart k0sworker (err=%v)", lastErr))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog("suspect: kubelet-syncloop-down - k0sworker not settled (<180s), skip restart")
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog("suspect: kubelet-syncloop-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-syncloop-down pleg-frozen (persisted %dx)",
			c.fails))
		c.fails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkSyncloop, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkSyncloop, "ok").Inc()
}

// kubeletBearer reads the service-account token kubelet's :10250
// webhook auth accepts — re-read every call so bound-token rotation
// needs no caching logic. Missing/unreadable file → "" (the probe
// runs unauthenticated and 401/403 marks the check inconclusive).
func (h *Hygiene) kubeletBearer() string {
	b, err := os.ReadFile(h.cfg.KubeletTokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ctrsockCheck is the A4 containerd-socket hang probe as a Check;
// it owns the consecutive-fail streak (ex-Hygiene.ctrsockFails).
type ctrsockCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ctrsockCheck) Name() string { return checkCtrSock }

// Run executes one containerd-sock round.
func (c *ctrsockCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCtrSock, "gated").Inc()
		return
	}
	err := c.h.cfg.probeUnixSock(ctx, c.h.cfg.ContainerdSocket, unixSockProbeTimeout)
	if err == nil {
		c.fails = 0
		c.h.state.Exit("containerd-sock-down", nil)
		c.h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down %s probe fail: %v (check %d/%d)",
			c.h.cfg.ContainerdSocket, err, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
		return
	}
	// BUG-H4: a hung containerd socket wedges PLEG and every pod
	// lifecycle op — confirmed consecutive fails self-heal through
	// the shared k0sworker restart gates, checkKubeletSyncloop
	// parity.
	overloaded := c.h.state.Exists("node-overloaded")
	if !overloaded {
		c.h.state.Enter("containerd-sock-down",
			fmt.Sprintf("probe_err=%v", err))
	} else if !c.h.state.Exists("containerd-sock-down") {
		c.h.state.AppendLog(fmt.Sprintf(
			"containerd-sock-down suppressed-overloaded - probe_err=%v", err))
	}
	switch {
	case overloaded:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: containerd-sock-down - node overloaded, skip restart k0sworker (err=%v)", err))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog("suspect: containerd-sock-down - k0sworker not settled (<180s), skip restart")
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog("suspect: containerd-sock-down - in restart cooldown (<30m), skip")
	default:
		// Budget already spent atomically by the rateTrySpend
		// case — the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - containerd-sock-down %s (persisted %dx)",
			c.h.cfg.ContainerdSocket, c.fails))
		c.fails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkCtrSock, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkCtrSock, "ok").Inc()
}

// --- Check: containerd stale ingest GC (A3 — 39-ctr-ingest-gc) ---
// A hard-reboot or OOM mid-pull leaves ingest dirs containerd never
// reaps; kubelet's ImageGC can't see them because the lease is
// orphaned. Runs when /var/lib/k0s is >75% full OR every 6h; ingest
// dirs with mtime >3h (no legitimate pull survives that) are removed
// via `ctr content ingest rm`, with a direct dir rm as fallback.
