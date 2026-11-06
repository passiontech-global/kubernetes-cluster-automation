// cilium_lrp.go — W7-H3 node-local-dns LRP datapath guard
// (CiliumLRPCheck): a Ready node-local-dns pod whose :53 UDP
// listener is wedged → delete the pod so the DaemonSet respawns it
// with a fresh socket.
package cilium

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
// The LRP datapath probe targets the kube-dns ClusterIP — the
// CiliumLocalRedirectPolicy's serviceMatcher redirects
// 10.96.0.10:53 to the local cache pod, so this exercises the
// real frontend→backend path from the host netns (socket-LB).
// 169.254.20.10 only exists in the legacy hostNetwork/iptables
// mode (calico cluster, where this check is dormant) — probing
// it on a cilium node always fails → false-positive pod kills.
)

// W7 pod matcher — anchored like konnPodRe/dnsPodRe.
var nldPodRe = regexp.MustCompile(`^node-local-dns-[a-z0-9]+$`) // H3 LRP DNS guard

// The dnsProbe seam default is probee.DNSQuery (the old probeDNSUDP
// verbatim) — one minimal A-record query to addr over UDP; any
// well-formed reply matching the query id proves :53 answers:
// NXDOMAIN/SERVFAIL still mean the listener is alive, silence means
// the LRP datapath is wedged.

// CiliumLRPCheck probes the node-local resolver's :53 listener
// while its pod claims Ready — a hung listener inside an LRP path
// blackholes cluster DNS node-wide. Confirmed for ConsecNeeded
// consecutive cycles → delete the node-local-dns pod on this node
// (the DaemonSet respawns it with a fresh socket; last-nld-restart
// 30m budget). Only evaluated on cilium nodes (cilium_host present)
// — calico nodes serve local DNS without the LRP datapath.
// CiliumLRPCheck is the W7-H3 node-local-dns datapath guard as a
// Check; it owns the :53 probe fail streak (ex-Hygiene.nldFails).
type CiliumLRPCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *CiliumLRPCheck) Name() string { return wdeps.CheckCiliumLRP }

// Run executes one cilium-lrp-dns round.
func (c *CiliumLRPCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.Cfg.Net.SysClassNet, "cilium_host")); err != nil {
		// No cilium datapath — the LRP wedge can't exist here.
		c.Fails = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "ok").Inc()
		return
	}
	// The plan gates on cilium-agent actually running: cilium_host
	// persists while the agent is down, and a dead/wedged agent can
	// break the :53 datapath itself — killing the nld pod then would
	// mask the real failure (wdeps.CheckCilium owns the agent-down verdict).
	agentTasks, ctrOK := ciliumAgentTasks(c.d)
	if !ctrOK {
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "abort").Inc()
		return
	}
	if len(agentTasks) == 0 {
		// Agent absent/dead — datapath verdict inconclusive; the LRP
		// check stands down rather than punish a healthy pod.
		c.Fails = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "gated").Inc()
		return
	}
	if !e.APIOK {
		// Inconclusive — keep the streak like the other API-gated
		// checks (a LIST flake must not count or clear evidence).
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "abort").Inc()
		return
	}
	var nld *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.Namespace == "kube-system" && nldPodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning &&
			wdeps.PodReady(p) {
			nld = p
			break
		}
	}
	if nld == nil {
		// No Ready node-local-dns pod → nothing owes a datapath
		// answer (not-Running/NotReady pods are kubelet's problem).
		c.Fails = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "ok").Inc()
		return
	}
	if c.d.Cfg.Seams.DNSProbe(c.d.Cfg.Net.LocalDNSProbeAddr, c.d.Cfg.Net.LocalDNSProbeName,
		ciliumProbeTime) {
		c.Fails = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "ok").Inc()
		return
	}
	c.Fails++
	if c.Fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe of %s failed while %s/%s Ready=True (check %d/%d)",
			c.d.Cfg.Net.LocalDNSProbeAddr, nld.Namespace, nld.Name,
			c.Fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "ok").Inc()
		return
	}
	if !c.d.State.RateTrySpend("last-nld-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe fails %dx but pod restart in cooldown (<30m), skip",
			c.Fails))
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: cilium-lrp-dns deleted pod %s/%s - :53 probe failed %dx while Ready=True (LRP datapath wedge)",
		nld.Namespace, nld.Name, c.Fails))
	if err := c.d.Cfg.Client.CoreV1().Pods(nld.Namespace).Delete(ctx, nld.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns delete %s/%s failed: %v",
			nld.Namespace, nld.Name, err))
	} else {
		c.d.Actions.WithLabelValues(wdeps.CheckCiliumLRP, "pod_delete").Inc()
	}
	c.Fails = 0
	c.d.Cycles.WithLabelValues(wdeps.CheckCiliumLRP, "ok").Inc()
}
