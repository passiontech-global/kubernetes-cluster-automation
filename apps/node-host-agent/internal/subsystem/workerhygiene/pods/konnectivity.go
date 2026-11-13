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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Regexes — anchored where the shell learned to anchor (the konn pod
// name and the DNS pod names MUST be anchored: unanchored ~= filters
// previously matched konnectivity-agent-patcher-* and coredns-* job
// pods → wrong pause killed, incident 2026-09-26).
var (
	// --node-ip=<ip> inside the k0sworker unit's ExecStart.
	nodeIPRe = regexp.MustCompile(`--node-ip=([0-9.]+)`)
	// --agent-identifiers=host=<ip> inside proxy-agent cmdline —
	// fallback when environ is unreadable. NEVER grep bare 'host='
	// (matches --proxy-server-host first — the false positive that
	// caused the 163x pause-kill loop of 2026-09-19..23).
	agentHostRe = regexp.MustCompile(`--agent-identifiers=host=([0-9.]+)`)
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

// deleteKonnectivityPod deletes this node's konnectivity-agent pod in
// kube-system (grace 5 — the Running DaemonSet pod gets a bounded
// shutdown window instead of an instant SIGKILL) — the DaemonSet
// recreates the pod with freshly baked env.
// Anchored name match + namespace pin (see KonnPodRe comment).
func DeleteKonnectivityPod(d *wdeps.Deps, ctx context.Context, pods []corev1.Pod) bool {
	// L1↔L3 hold: deleting the konnectivity agent mid cluster-
	// maintenance severs the very control path a drain needs.
	if d.HoldLocalAction(ctx) {
		d.State.AppendLog("suspect: konnectivity pod delete held — " +
			"cluster maintenance in progress")
		return false
	}
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" || !KonnPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil {
			continue
		}
		// The heal stamp rides BEFORE the delete so the cluster side
		// sees the attribution even if this process dies mid-call.
		d.StampPodHealed(ctx, p.Namespace, p.Name)
		if err := d.Cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
			metav1.DeleteOptions{
				GracePeriodSeconds: ptr.To[int64](5),
				// UID precondition: the listing→delete window can
				// outlive this pod — a same-named recycle (DS churn)
				// is not ours to kill.
				Preconditions: &metav1.Preconditions{UID: &p.UID},
			}); err != nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: konnectivity pod delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue // a stale entry must not block the next candidate
		}
		return true
	}
	return false
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
	if c.Fails >= c.d.Cfg.ConsecNeeded &&
		c.d.State.RateTrySpend("last-konn-restart", c.d.Cfg.MinRestartInterval) {
		// Budget spent atomically BEFORE acting — a failed action
		// still consumed it (conservative, rate_spend parity).
		c.Fails = 0
		// NPD contract: "recreating konnectivity-agent ..." fires the
		// KonnectivityStaleId filelog pattern.
		c.d.State.AppendLog("KONNECTIVITY-IP-RESTART: " +
			latchdefs.ReasonKonnectivityAgentRecreate +
			fmt.Sprintf(" sandbox - stale identifier host=%s != node-ip=%s",
				agentHost, nodeIP))
		if DeleteKonnectivityPod(c.d, ctx, e.Pods) {
			c.d.Actions.WithLabelValues(wdeps.CheckKonn, "pod_delete").Inc()
		} else if stalePID > 0 {
			// No API pod found (list failed or pod renamed) — kill
			// the stale proxy-agent directly. Least-bad: a container
			// restart alone can't fix env baked at pod create, but
			// it still clears a hung agent while humans look.
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
