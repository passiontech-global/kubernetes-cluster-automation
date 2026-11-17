// konnectivity.go — the 30-konnectivity stale-identifier guard
// (30-konnectivity.sh port): proxy-agent processes baked with a
// stale --node-ip get their pod recreated (or the stale process
// killed when no API pod is found). Anchored-name regexes are
// load-bearing — see the KonnPodRe comment.
package pods

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Regexes — anchored where the shell learned to anchor (the konn pod
// name and the DNS pod names MUST be anchored: unanchored ~= filters
// previously matched konnectivity-agent-patcher-* and coredns-* job
// pods → wrong pause killed, incident 2026-09-26).
var (
	// --node-ip=<ip> inside the k0sworker unit's ExecStart. The
	// value class is deliberately wide — IPv6 literals and
	// hostnames are legal node identifiers, and a narrow [0-9.]+
	// silently read them as "no node-ip" (inconclusive forever).
	// \s/& bound the capture: unit-file and cmdline args are
	// space-separated, and & is the shell background operator.
	nodeIPRe = regexp.MustCompile(`--node-ip=([^\s&]+)`)
	// --agent-identifiers=host=<ip> inside proxy-agent cmdline —
	// fallback when environ is unreadable. NEVER grep bare 'host='
	// (matches --proxy-server-host first — the false positive that
	// caused the 163x pause-kill loop of 2026-09-19..23).
	agentHostRe = regexp.MustCompile(`--agent-identifiers=host=([^\s&]+)`)
	// DaemonSet pod names only (anchored — see comment block above).
	KonnPodRe = regexp.MustCompile(`^konnectivity-agent-[a-z0-9]+$`)
)

// k0sWorkerNodeIP reads --node-ip=<ip> out of the k0sworker unit —
// the node's InternalIP konnectivity-agent should have baked in.
func k0sWorkerNodeIP(d *wdeps.Deps) string {
	data, err := os.ReadFile(d.Cfg.K0sWorkerUnitFile)
	if err != nil {
		return ""
	}
	if m := nodeIPRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// proxyAgentComm reports whether the pid's comm can carry a
// proxy-agent argv — the dedicated proxy-agent binary or the
// konnectivity-agent (stat comm truncates to "konnectivity-agen").
// known=false (unreadable stat) means "cannot rule the pid out" —
// the caller falls through to the cmdline read as before.
func proxyAgentComm(e *wdeps.CycleEnv, d *wdeps.Deps, pid int) (match, known bool) {
	var comm string
	if e != nil && e.StatsOnce != nil {
		if st, ok := e.StatsOnce()[pid]; ok && st.HasComm {
			comm, known = st.Comm, true
		}
	} else if st, ok := d.Proc.Stat(pid); ok && st.HasComm {
		comm, known = st.Comm, true
	}
	if !known {
		return false, false
	}
	return strings.Contains(comm, "proxy") ||
		strings.HasPrefix(comm, "konnectivity"), true
}

// isProxyAgent matches `pgrep -f 'proxy-agent --'` on the joined
// cmdline (the bare "/proxy-agent" prefix covers argv[0]-only forms).
func isProxyAgent(argv []string) bool {
	// Shell parity: `pgrep -f 'proxy-agent --'` — the trailing
	// space/dash keeps /proxy-agent-foo lookalikes out.
	joined := strings.Join(argv, " ")
	return strings.HasPrefix(joined, "/proxy-agent ") ||
		strings.Contains(joined, "proxy-agent --")
}

// proxyAgentHost returns the host identifier baked into the agent:
// NODE_IP from environ (downward status.hostIP, set at pod create),
// falling back to --agent-identifiers=host=<ip> on the cmdline.
func proxyAgentHost(d *wdeps.Deps, pid int, argv []string) string {
	if v := d.Proc.EnvValue(pid, "NODE_IP"); v != "" {
		return v
	}
	if m := agentHostRe.FindStringSubmatch(strings.Join(argv, " ")); m != nil {
		return m[1]
	}
	return ""
}

// KonnDeleteResult is the tri-state outcome of DeleteKonnectivityPod.
// The caller MUST distinguish KonnNoPod (no matching pod exists —
// the stale-process fallback may run) from KonnHeldOrErr (maintenance
// hold or a failed DELETE — the API is unwell, so killing the agent
// blind would sever the very control path a recovery needs).
type KonnDeleteResult int

const (
	KonnDeleted KonnDeleteResult = iota
	KonnHeldOrErr
	KonnNoPod
)

// DeleteKonnectivityPod deletes this node's konnectivity-agent pod in
// kube-system (grace 5 — the Running DaemonSet pod gets a bounded
// shutdown window instead of an instant SIGKILL) — the DaemonSet
// recreates the pod with freshly baked env.
// Anchored name match + namespace pin (see KonnPodRe comment).
func DeleteKonnectivityPod(d *wdeps.Deps, ctx context.Context, pods []corev1.Pod) KonnDeleteResult {
	// L1↔L3 hold: deleting the konnectivity agent mid cluster-
	// maintenance severs the very control path a drain needs.
	if d.HoldLocalAction(ctx) {
		d.State.AppendLog("suspect: konnectivity pod delete held — " +
			"cluster maintenance in progress")
		return KonnHeldOrErr
	}
	sawErr := false
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" || !KonnPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil {
			continue
		}
		if err := d.DeletePodGraceful(ctx, p); err != nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: konnectivity pod delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			sawErr = true
			continue // a stale entry must not block the next candidate
		}
		return KonnDeleted
	}
	if sawErr {
		return KonnHeldOrErr
	}
	return KonnNoPod
}

// KonnCheck is the 30-konnectivity stale-identifier guard as a
// Check; it owns the mismatch streak (ex-Hygiene.konnFails).
type KonnCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *KonnCheck) Name() string { return wdeps.CheckKonn }

// Run executes one konnectivity round.
func (c *KonnCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckKonn) {
		return
	}
	nodeIP := k0sWorkerNodeIP(c.d)
	// Healthy = ANY proxy-agent process baked with the current node
	// IP. Scan ALL processes, never take the first match: an orphaned
	// agent (task dir gone, process alive under a dead shim) keeps its
	// old NODE_IP and usually has the lower pid — first-match would
	// read the orphan's environ and report "stale" forever
	// (incident 2026-09-19..23: 163 pause kills). Only when NO
	// process matches do we suspect.
	healthy := false
	agentHost := ""
	stalePID := 0
	for _, pid := range e.PidsOnce() {
		// Comm pre-filter: only proxy/konnectivity comms can match
		// isProxyAgent — every other pid skips the cmdline read.
		if match, known := proxyAgentComm(e, c.d, pid); known && !match {
			continue
		}
		argv := c.d.Proc.Cmdline(pid)
		if !isProxyAgent(argv) {
			continue
		}
		phost := proxyAgentHost(c.d, pid, argv)
		if nodeIP != "" && phost == nodeIP {
			healthy = true
			break
		}
		if phost != "" && agentHost == "" {
			agentHost = phost
			stalePID = pid
		}
	}

	if healthy || nodeIP == "" || agentHost == "" {
		// Healthy or inconclusive (no node-ip parsed / no proxy-agent
		// found — e.g. konnectivity not deployed): reset, drop latch.
		c.Fails = 0
		c.d.State.Exit(latchdefs.LatchKonnectivityIPMismatch, nil)
		c.d.CycleResult(wdeps.CheckKonn, "ok")
		return
	}

	c.Fails++
	c.d.State.Enter(latchdefs.LatchKonnectivityIPMismatch,
		fmt.Sprintf("host=%s node-ip=%s", agentHost, nodeIP))
	if c.Fails >= c.d.Cfg.ConsecNeeded {
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog("suspect: konnectivity pod delete held — cluster maintenance in progress")
		} else if c.d.State.RateTrySpend("last-konn-restart", c.d.Cfg.MinRestartInterval) {
			// Budget spent atomically BEFORE acting — a failed action
			// still consumed it (conservative, rate_spend parity).
			c.Fails = 0
			// NPD contract: "recreating konnectivity-agent ..." fires the
			// KonnectivityStaleId filelog pattern.
			c.d.State.AppendLog("KONNECTIVITY-IP-RESTART: " +
				latchdefs.ReasonKonnectivityAgentRecreate +
				fmt.Sprintf(" sandbox - stale identifier host=%s != node-ip=%s",
					agentHost, nodeIP))
			switch DeleteKonnectivityPod(c.d, ctx, e.Pods) {
			case KonnDeleted:
				c.d.Actions.WithLabelValues(wdeps.CheckKonn, "pod_delete").Inc()
			case KonnNoPod:
				// The fallback SIGKILL is only safe when the pod LIST
				// was healthy: !e.APIOK means e.Pods may be empty
				// because the read failed, not because no agent pod
				// exists — and killing the agent while the API is
				// unwell severs the control path the recovery needs.
				if !e.APIOK {
					c.d.State.AppendLog("suspect: konnectivity stale-id " +
						"remediation held — apiserver unhealthy, proxy-agent kept")
				} else if stalePID > 0 {
					// No API pod found (list succeeded but pod renamed)
					// — kill the stale proxy-agent directly. Least-bad:
					// a container restart alone can't fix env baked at
					// pod create, but it still clears a hung agent
					// while humans look.
					if err := c.d.Cfg.Seams.Host.KillFn(stalePID, syscall.SIGKILL); err != nil {
						c.d.State.AppendLog(fmt.Sprintf(
							"suspect: kill stale proxy-agent pid=%d failed: %v", stalePID, err))
					} else {
						c.d.State.AppendLog(fmt.Sprintf(
							"ACTION: killed stale proxy-agent pid=%d — no API pod found",
							stalePID))
					}
					c.d.Actions.WithLabelValues(wdeps.CheckKonn, "sigkill").Inc()
				}
			default: // KonnHeldOrErr — maintenance hold or delete error; keep the agent
			}
		}
	} else {
		// NPD contract: "konnectivity stale identifier ..." fires the
		// same KonnectivityStaleId pattern while accumulating.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: "+latchdefs.ReasonKonnectivityStaleID+
				" host=%s != node-ip=%s%s",
			agentHost, nodeIP,
			checkkit.Progress(c.Fails, c.d.Cfg.ConsecNeeded)))
	}
	c.d.CycleResult(wdeps.CheckKonn, "ok")
}
