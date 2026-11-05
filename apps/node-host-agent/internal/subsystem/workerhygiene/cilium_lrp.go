// cilium_lrp.go — W7-H3 node-local-dns LRP datapath guard
// (ciliumLRPCheck): a Ready node-local-dns pod whose :53 UDP
// listener is wedged → delete the pod so the DaemonSet respawns it
// with a fresh socket.
package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// The dnsProbe seam default is probee.DNSQuery (the old probeDNSUDP
// verbatim) — one minimal A-record query to addr over UDP; any
// well-formed reply matching the query id proves :53 answers:
// NXDOMAIN/SERVFAIL still mean the listener is alive, silence means
// the LRP datapath is wedged.

// checkCiliumLRPDNS probes the node-local resolver's :53 listener
// while its pod claims Ready — a hung listener inside an LRP path
// blackholes cluster DNS node-wide. Confirmed for ConsecNeeded
// consecutive cycles → delete the node-local-dns pod on this node
// (the DaemonSet respawns it with a fresh socket; last-nld-restart
// 30m budget). Only evaluated on cilium nodes (cilium_host present)
// — calico nodes serve local DNS without the LRP datapath.
// ciliumLRPCheck is the W7-H3 node-local-dns datapath guard as a
// Check; it owns the :53 probe fail streak (ex-Hygiene.nldFails).
type ciliumLRPCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ciliumLRPCheck) Name() string { return checkCiliumLRP }

// Run executes one cilium-lrp-dns round.
func (c *ciliumLRPCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumLRP, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.h.cfg.Net.SysClassNet, "cilium_host")); err != nil {
		// No cilium datapath — the LRP wedge can't exist here.
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	// The plan gates on cilium-agent actually running: cilium_host
	// persists while the agent is down, and a dead/wedged agent can
	// break the :53 datapath itself — killing the nld pod then would
	// mask the real failure (checkCilium owns the agent-down verdict).
	agentTasks, ctrOK := c.h.ciliumAgentTasks()
	if !ctrOK {
		c.h.cycles.WithLabelValues(checkCiliumLRP, "abort").Inc()
		return
	}
	if len(agentTasks) == 0 {
		// Agent absent/dead — datapath verdict inconclusive; the LRP
		// check stands down rather than punish a healthy pod.
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "gated").Inc()
		return
	}
	if !e.apiOK {
		// Inconclusive — keep the streak like the other API-gated
		// checks (a LIST flake must not count or clear evidence).
		c.h.cycles.WithLabelValues(checkCiliumLRP, "abort").Inc()
		return
	}
	var nld *corev1.Pod
	for i := range e.pods {
		p := &e.pods[i]
		if p.Namespace == "kube-system" && nldPodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning &&
			podReady(p) {
			nld = p
			break
		}
	}
	if nld == nil {
		// No Ready node-local-dns pod → nothing owes a datapath
		// answer (not-Running/NotReady pods are kubelet's problem).
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	if c.h.cfg.Seams.dnsProbe(c.h.cfg.Net.LocalDNSProbeAddr, c.h.cfg.Net.LocalDNSProbeName,
		ciliumProbeTime) {
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe of %s failed while %s/%s Ready=True (check %d/%d)",
			c.h.cfg.Net.LocalDNSProbeAddr, nld.Namespace, nld.Name,
			c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	if !c.h.state.RateTrySpend("last-nld-restart", c.h.cfg.MinRestartInterval) {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe fails %dx but pod restart in cooldown (<30m), skip",
			c.fails))
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	c.h.state.AppendLog(fmt.Sprintf(
		"ACTION: cilium-lrp-dns deleted pod %s/%s - :53 probe failed %dx while Ready=True (LRP datapath wedge)",
		nld.Namespace, nld.Name, c.fails))
	if err := c.h.cfg.Client.CoreV1().Pods(nld.Namespace).Delete(ctx, nld.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns delete %s/%s failed: %v",
			nld.Namespace, nld.Name, err))
	} else {
		c.h.actions.WithLabelValues(checkCiliumLRP, "pod_delete").Inc()
	}
	c.fails = 0
	c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
}

// checkCiliumLRPDNS forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumLRPDNS(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.ciliumLRP.Run(ctx, &cycleEnv{
		pods: pods, apiOK: apiOK, workerActive: workerActive})
}
