// kubelet_feeder.go — the T15 kubelet watchdog feeder + remediate
// (k0s-kubelet-watchdog.sh + k0sworker-remediate.sh ports): the
// forever feeder loop, its activation gate and the ordered G0–G6
// remediate gates that guard a k0sworker restart.
package workerhygiene

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// T15 kubelet watchdog feeder defaults (k0s-kubelet-watchdog.sh). The
// shell unit probed every 20s inside a 200s WatchdogSec grace —
// ~200s of continuous silence before the remediate oneshot ran.
// The agent deliberately tightens this to a 15s cadence with
// KWD_MAX_FAIL=4 consecutive fails (~60s) and NO additional grace:
// detection is faster, and the shell's slack is replaced by the
// remediate Gate-0 re-probe + the ordered gates (every one is a
// chance to stop before the restart). curl --max-time 5 bounds
// every probe.
const (
	defaultKubeletWdInterval   = 15 * time.Second
	defaultKubeletWdMaxFail    = 4
	defaultKubeletWdProbeURL   = "http://127.0.0.1:10248/healthz"
	defaultKubeletWdReprobeGap = 3 * time.Second // remediate Gate-0: two probes ~3s apart
	// G4 fallback when no API backends are configured — the
	// worker-local api-local-lb listener (k0s haproxy).
	defaultAPIFallbackURL = "https://localhost:7443/livez"
	kubeletWdProbeTimeout = 5 * time.Second
	apiLivezProbeTimeout  = 5 * time.Second
)

// --- Check: ctr-tasks (31-ctr-tasks.sh) ---

// runKubeletFeeder is the T15 feeder's forever loop — returns only
// when ctx is cancelled. The tick self-gates per round; the "start"
// line is logged on each activation transition inside the tick, not
// here — the goroutine also runs on nodes where the feeder never
// activates.
func (d *deps) runKubeletFeeder(ctx context.Context) {
	cycle.Every("kubelet-feeder", d.cfg.Kubelet.WdInterval,
		d.kubeletFeedTick).Run(ctx)
}

// kubeletFeederActive reports whether the feeder should probe this
// node — the shell install gate: the unit ran only on hosts listed in
// systemd_watchdog_hosts (KubeletWatchdogHosts); in-agent the check
// ALSO passes by default on any worker node (k0sworker.service
// present — the pilot graduated fleet-wide). WD_SIG_KUBELET_WATCHDOG
// =off is the per-module kill switch, honoured live via WatchdogSrc.
func (d *deps) kubeletFeederActive() bool {
	if wd := d.feederWatchdogConf(); wd != nil && !wd.SignalEnabled(checkKubeletWd) {
		return false
	}
	for _, name := range d.cfg.Kubelet.WatchdogHosts {
		if name == d.cfg.NodeName {
			return true
		}
	}
	_, err := os.Stat(d.cfg.K0sWorkerUnitFile)
	return err == nil
}

// feederWatchdogConf returns the freshest parsed node-watchdog.conf
// WITHOUT mutating cfg — Cycle refreshes cfg.Watchdog itself; the
// feeder goroutine must never write cfg fields (data race).
func (d *deps) feederWatchdogConf() *watchdogconf.Config {
	if d.cfg.WatchdogSrc != nil {
		return d.cfg.WatchdogSrc.Get()
	}
	// Without a reloader cfg.Watchdog is immutable — Cycle's refresh
	// block is guarded by WatchdogSrc != nil too.
	return d.cfg.Watchdog
}

// --- kubelet watchdog feeder + remediate (T15) ---
// Port of scripts/k0s-kubelet-watchdog.sh + k0sworker-remediate.sh.
// The shell feeder was a dedicated systemd unit (k0sworker-watchdog)
// feeding WATCHDOG=1 into its own WatchdogSec and dying `exit 1`
// after KWD_MAX_FAIL consecutive :10248 failures — OnFailure then ran
// the remediate oneshot. In-agent there is no watchdog unit to feed:
// the agent IS the loop — probe every KubeletWdInterval, and on
// KubeletWdMaxFail consecutive fails (~60s) run the same ordered
// gates inline, then re-arm like the unit's Restart=always.
//
// Remediate gates (k0sworker-remediate.sh order — every SKIP exits
// without action; restart only when ALL agree):
//   G0 re-probe :10248 twice ~3s apart → one "ok" = steal blip,
//                                      self-correct (the shell's
//                                      Gate-1, numbered G0 here so the
//                                      existing G1–G6 strings stay)
//   G1 uptime <1200s                 → fresh boot, kubelet still up-coming
//   G2 k0sworker active <180s        → settle window (kubelet init)
//   G3 state-node-overloaded latched → wedge is a load symptom
//   G4 no API backend answers /livez → node isolated, restart = churn
//   G5 last-restart <30m             → shared budget spent → latch
//                                      state-kubelet-healthz-down so
//                                      NHC→SNR escalates to reboot
//   G6 spend budget + reset-failed + systemctl restart k0sworker

// kubeletFeedTick is one feeder round: probe :10248, count fails, run
// the remediate gates at MaxFail — k0s-kubelet-watchdog.sh's loop
// body minus the sd_notify feed (no watchdog unit exists in-agent).
func (d *deps) kubeletFeedTick(ctx context.Context) {
	active := d.kubeletFeederActive()
	if active && !d.kubeletFeederWasActive {
		// false→true activation (first active tick, node re-added to
		// systemd_watchdog_hosts, unit file reinstalled, WD_SIG
		// lifted) — a partial fail-streak from before the gap is
		// stale evidence and must not count toward a restart.
		d.state.AppendLog(fmt.Sprintf(
			"kubelet-feeder: start interval=%ds maxfail=%d url=%s",
			int(d.cfg.Kubelet.WdInterval.Seconds()), d.cfg.Kubelet.WdMaxFail,
			d.cfg.Kubelet.WdProbeURL))
		if d.kubeletWdFails > 0 {
			d.state.AppendLog(fmt.Sprintf(
				"kubelet-feeder: re-activated — dropping %d stale fails", d.kubeletWdFails))
		}
		d.kubeletWdFails = 0
	}
	d.kubeletFeederWasActive = active
	if !active {
		return
	}
	if d.cfg.Seams.probeBodyOK(ctx, d.cfg.Kubelet.WdProbeURL, kubeletWdProbeTimeout) {
		if d.kubeletWdFails > 0 {
			d.state.AppendLog(fmt.Sprintf(
				"kubelet-feeder: probe OK again after %d fail", d.kubeletWdFails))
		}
		d.kubeletWdFails = 0
		d.state.Exit(hoststate.LatchKubeletHealthzDown, nil)
		return
	}
	// PartOf=k0sworker.service parity: the shell feeder unit stood
	// down with k0sworker — an intentionally inactive worker must not
	// accumulate fails toward a restart it doesn't want, and must not
	// keep a healthz-down latch that escalates a deliberate stop into
	// an NHC→SNR reboot.
	if d.cfg.Systemd != nil {
		active, err := d.cfg.Systemd.Active(ctx, "k0sworker.service")
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
			if d.kubeletWdFails > 0 {
				d.state.AppendLog("kubelet-feeder: k0sworker not active — fails reset (PartOf parity)")
			}
			d.kubeletWdFails = 0
			d.state.Exit(hoststate.LatchKubeletHealthzDown, nil)
			return
		}
	}
	d.kubeletWdFails++
	d.state.AppendLog(fmt.Sprintf("kubelet-feeder: probe fail %d/%d",
		d.kubeletWdFails, d.cfg.Kubelet.WdMaxFail))
	if d.kubeletWdFails < d.cfg.Kubelet.WdMaxFail {
		return
	}
	d.state.AppendLog(fmt.Sprintf(
		"kubelet-feeder: %d consecutive fails (~%ds) — running remediation gates",
		d.kubeletWdFails,
		int(d.cfg.Kubelet.WdInterval.Seconds())*d.cfg.Kubelet.WdMaxFail))
	d.runKubeletRemediate(ctx)
	// Re-arm like the shell's exit-1 → unit fail → OnFailure →
	// Restart=always round: the remediate pass ENDS this fails run
	// whatever the gates decided.
	d.kubeletWdFails = 0
}

// runKubeletRemediate is the ordered-gate port of
// k0sworker-remediate.sh — a probe failure does NOT prove the kubelet
// is dead (the probe may just be timing out under steal); every gate
// is a chance to stop before the shared last-restart budget is spent.
func (d *deps) runKubeletRemediate(ctx context.Context) {
	d.actions.WithLabelValues(checkKubeletWd, "remediate").Inc()
	d.state.AppendLog("kubelet-remediate: healthz :10248 down ~60s — running ordered gates before k0sworker restart")

	// G0 re-probe — the shell's Gate 1: probe :10248 twice ~3s apart
	// before ANYTHING else. Four failed ticks do not prove a dead
	// kubelet — under CPU steal the probes themselves time out, and
	// the ~60s streak may already be over. One "ok" → self-correct
	// (drop the fail streak and any escalation latch), never spend a
	// restart on a healthy kubelet.
	for i := 1; i <= 2; i++ {
		if d.cfg.Seams.probeBodyOK(ctx, d.cfg.Kubelet.WdProbeURL, kubeletWdProbeTimeout) {
			d.state.AppendLog(fmt.Sprintf(
				"kubelet-remediate: SKIP(G0-reprobe) :10248 answered 'ok' on re-probe %d — false alarm (steal blip), self-correcting", i))
			d.kubeletWdFails = 0
			d.state.Exit(hoststate.LatchKubeletHealthzDown, nil)
			return
		}
		if i < 2 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d.cfg.Kubelet.WdReprobeGap):
			}
		}
	}
	d.state.AppendLog("kubelet-remediate: G0 :10248 still dead after 2 re-probes — continuing ordered gates")

	// G1 uptime (WD_REQUIRES: uptime) — a node <20m up is still
	// bringing kubelet online; a restart inside the window only churns.
	if up, err := d.proc.UptimeSeconds(); err == nil && up < minUptimeSeconds {
		d.state.AppendLog(fmt.Sprintf(
			"kubelet-remediate: SKIP(G1-uptime) uptime %.0fs < %ds", up, minUptimeSeconds))
		return
	}

	// G2 settle — k0sworker ActiveEnterTimestampMonotonic younger than
	// the 180s settle window: the kubelet from the previous restart may
	// still be initialising; spending the budget now just resets that
	// init cycle. An unreadable timestamp also skips (never restart
	// blind).
	if !d.k0sWorkerSettled(ctx) {
		d.state.AppendLog("kubelet-remediate: SKIP(G2-settle) k0sworker active <180s or timestamp unreadable")
		return
	}

	// G3 overload — a kubelet wedge under CPU starvation is a
	// symptom, not a dead kubelet; restarting dumps its load onto the
	// surviving nodes (amplifier).
	if d.state.Exists(hoststate.LatchNodeOverloaded) {
		d.state.AppendLog("kubelet-remediate: SKIP(G3-overload) state-node-overloaded latched")
		return
	}

	// G4 apiserver — a node that reaches NO API backend is isolated;
	// restarting kubelet only adds a NotReady blip + resync churn.
	if !d.anyAPIBackendLive(ctx) {
		d.state.AppendLog("kubelet-remediate: SKIP(G4-apiserver) no API backend answers /livez — node isolated")
		return
	}

	// G5 rate-limit — the last-restart budget is SHARED with every
	// other k0sworker restart source (30m), including the Cycle checks
	// running on their own goroutine — the check+spend is atomic
	// (rateTrySpend) or a stall/watch restart could pass the same
	// window and double-restart. Exhausted → escalate to the NHC→SNR
	// reboot path via the latch instead of piling on.
	if !d.state.RateTrySpend("last-restart", d.cfg.MinRestartInterval) {
		d.state.Enter(hoststate.LatchKubeletHealthzDown, "restart-budget-exhausted")
		d.state.AppendLog("kubelet-remediate: SKIP(G5-ratelimit) k0sworker restart <30m ago — " +
			"state-kubelet-healthz-down latched (NHC→SNR escalation)")
		return
	}

	// G6 act — the budget was already spent atomically above (shell
	// parity: a hung/failed restart still consumed it). reset-failed
	// first so a stale failed state can't wedge the unit's next start.
	d.state.AppendLog(fmt.Sprintf(
		"ACTION: restarting k0sworker (reason=systemd-watchdog-kubelet-healthz-60s fails=%d)",
		d.cfg.Kubelet.WdMaxFail))
	d.resetFailedK0sWorker(ctx)
	if err := d.restartK0sWorker(ctx); err != nil {
		d.state.AppendLog(fmt.Sprintf(
			"kubelet-remediate: G6 restart k0sworker FAIL: %v (budget spent)", err))
		return
	}
	d.state.AppendLog("kubelet-remediate: G6 k0sworker restarted")
	d.actions.WithLabelValues(checkKubeletWd, "restart").Inc()
}

// anyAPIBackendLive is the G4 probe — the shell TCP-checked the
// apiserver endpoint (API_PROBE_HOSTPORT/kubelet.conf) before
// declaring the node isolated; the agent GETs /livez on every
// configured API backend (API_BACKENDS, ports preserved) and counts
// ANY HTTP response as reachable (curl -sk parity — even a 500 means
// the listener is alive). With no backends configured it falls back
// to the worker-local api-local-lb listener (APIFallbackURL).
func (d *deps) anyAPIBackendLive(ctx context.Context) bool {
	var urls []string
	if wd := d.feederWatchdogConf(); wd != nil {
		for _, b := range wd.APIBackends {
			if b.Addr != "" {
				urls = append(urls,
					"https://"+withDefaultAPIPort(b.Addr)+"/livez")
			}
		}
	}
	if len(urls) == 0 && d.cfg.WatchdogSrc == nil {
		// No reloader → cfg.APIBackends is immutable (Cycle refreshes
		// it from the conf only when a reloader exists).
		for _, a := range d.cfg.APIBackends {
			urls = append(urls, "https://"+withDefaultAPIPort(a)+"/livez")
		}
	}
	if len(urls) == 0 {
		urls = []string{d.cfg.Kubelet.APIFallbackURL}
	}
	for _, url := range urls {
		// probeHTTPStatus, not probeHTTP: the verdict is liveness,
		// so ANY HTTP code — even 401/403/500 — proves the listener
		// answered (curl -sk parity; a 2xx-only read made an
		// auth-refusing or LB-degraded endpoint look "unreachable"
		// and falsely gated remediation as isolated).
		if _, err := d.cfg.Seams.probeHTTPStatus(ctx, url, "",
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
func (d *deps) resetFailedK0sWorker(ctx context.Context) {
	if d.cfg.Systemd == nil {
		return
	}
	if out, err := d.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "k0sworker.service"); err != nil {
		d.state.AppendLog(fmt.Sprintf(
			"kubelet-remediate: reset-failed k0sworker failed: %v (%s)",
			err, strings.TrimSpace(out)))
	}
}
