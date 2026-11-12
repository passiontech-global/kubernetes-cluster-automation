// cilium_lrp.go — envoy-xds-lrp node-local-dns LRP datapath guard
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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// endpointSliceServiceLabel is the kubernetes.io/service-name
// label key endpointslices carry for their owning Service — the
// discovery.k8s.io lookup key for serviceReadyEndpoints.
const endpointSliceServiceLabel = "kubernetes.io/service-name"

const (
// The LRP datapath probe targets the kube-dns ClusterIP — the
// CiliumLocalRedirectPolicy's serviceMatcher redirects
// 10.96.0.10:53 to the local cache pod, so this exercises the
// real frontend→backend path from the host netns (socket-LB).
// 169.254.20.10 only exists in the legacy hostNetwork/iptables
// mode (calico cluster, where this check is dormant) — probing
// it on a cilium node always fails → false-positive pod kills.
)

// pod matcher — anchored like konnPodRe/dnsPodRe.
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
// CiliumLRPCheck is the envoy-xds-lrp node-local-dns datapath guard as a
// Check; it owns the :53 probe fail streak (ex-Hygiene.nldFails)
// plus the BPF service-map desync streak (svcFails — an apiserver
// Service with Ready endpoints whose local BPF map entry has 0
// backends means the agent stopped programming, which also explains
// any :53 datapath wedge — the desync section gates the nld pod
// delete below).
type CiliumLRPCheck struct {
	d        *wdeps.Deps
	Fails    int
	svcFails int
}

// Name returns the check label / WD_SIG key.
func (c *CiliumLRPCheck) Name() string { return wdeps.CheckCiliumLRP }

// Run executes one cilium-lrp-dns round.
func (c *CiliumLRPCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCiliumLRP) {
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.Cfg.SysClassNet, "cilium_host")); err != nil {
		// No cilium datapath — the LRP wedge can't exist here.
		c.Fails = 0
		c.svcFails = 0
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
		return
	}
	// The plan gates on cilium-agent actually running: cilium_host
	// persists while the agent is down, and a dead/wedged agent can
	// break the :53 datapath itself — killing the nld pod then would
	// mask the real failure (wdeps.CheckCilium owns the agent-down verdict).
	agentTasks, ctrOK := ciliumAgentTasks(c.d, e)
	if !ctrOK {
		c.d.CycleResult(wdeps.CheckCiliumLRP, "abort")
		return
	}
	if len(agentTasks) == 0 {
		// Agent absent/dead — datapath verdict inconclusive; the LRP
		// check stands down rather than punish a healthy pod.
		c.Fails = 0
		c.svcFails = 0
		c.d.CycleResult(wdeps.CheckCiliumLRP, "gated")
		return
	}
	if !e.APIOK {
		// Inconclusive — keep the streak like the other API-gated
		// checks (a LIST flake must not count or clear evidence).
		c.d.CycleResult(wdeps.CheckCiliumLRP, "abort")
		return
	}
	// BPF service-map desync runs BEFORE the nld datapath verdict:
	// a kube-dns entry with apiserver-Ready endpoints but zero
	// programmed backends explains every :53 failure — deleting the
	// nld pod then punishes the wrong component.
	if c.serviceDesync(ctx, e, agentTasks) {
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
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
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
		return
	}
	// The :53 datapath must answer on BOTH transports — resolvers
	// query UDP first but truncated/large answers and TCP clients
	// (zone transfers, some resolvers) ride TCP; a one-sided wedge
	// still blackholes real queries.
	udpOK := c.d.Cfg.Seams.Probe.DNSProbe(ctx, c.d.Cfg.Net.LocalDNSProbeAddr,
		c.d.Cfg.Net.LocalDNSProbeName, ciliumProbeTime)
	tcpOK := c.d.Cfg.Seams.Probe.DNSProbeTCP(ctx, c.d.Cfg.Net.LocalDNSProbeAddr,
		c.d.Cfg.Net.LocalDNSProbeName, ciliumProbeTime)
	if udpOK && tcpOK {
		c.Fails = 0
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
		return
	}
	if c.d.StreakPending(&c.Fails, fmt.Sprintf(
		"suspect: cilium-lrp-dns :53 probe of %s failed (udp=%v tcp=%v) while %s/%s Ready=True",
		c.d.Cfg.Net.LocalDNSProbeAddr, udpOK, tcpOK,
		nld.Namespace, nld.Name)) {
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
		return
	}
	// Hold BEFORE the budget spend (same rule the spegel/calico
	// remedies carry): a maintenance-held delete must not consume
	// the restart cooldown for an action that never ran.
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog("suspect: cilium-lrp-dns pod delete held — " +
			"cluster maintenance in progress")
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
		return
	}
	if !c.d.State.RateTrySpend("last-nld-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe fails %dx but pod restart in cooldown (<30m), skip",
			c.Fails))
		c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	// The heal stamp rides BEFORE the delete so the cluster side sees
	// the attribution even if this process dies mid-call.
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: cilium-lrp-dns deleted pod %s/%s - :53 probe failed %dx while Ready=True (LRP datapath wedge)",
		nld.Namespace, nld.Name, c.Fails))
	c.d.StampPodHealed(ctx, nld.Namespace, nld.Name)
	if err := c.d.Cfg.Client.CoreV1().Pods(nld.Namespace).Delete(ctx, nld.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](5),
			// Same precondition the calico/spegel remedies carry: the
			// listing→delete window can outlive this pod, and a
			// same-named DS recycle is not ours to kill.
			Preconditions: &metav1.Preconditions{UID: &nld.UID},
		}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns delete %s/%s failed: %v",
			nld.Namespace, nld.Name, err))
	} else {
		c.d.Actions.WithLabelValues(wdeps.CheckCiliumLRP, "pod_delete").Inc()
	}
	c.Fails = 0
	c.d.CycleResult(wdeps.CheckCiliumLRP, "ok")
}

// --- local BPF service-map desync ---
// The agent can be alive and healthz-green while its BPF service
// map stopped tracking the apiserver: kube-dns or kubernetes show
// Ready endpoints server-side but the local map carries 0 backends
// — every socket-LB service lookup on this node resolves to nothing
// (a silent cluster-DNS outage the nld pod can't fix). The evidence
// comes from the Seams.Cilium.ServiceBackends read (GET /v1/service —
// `cilium-dbg service list -o json` equivalent). An unreadable map
// is inconclusive — never counted. ConsecNeeded consecutive desync
// cycles restart cilium-agent through the shared
// last-cilium-restart 30m budget (SIGKILL — kubelet restarts it).

// desyncServices are the apiserver Services whose Ready-endpoints
// state is cross-checked against the local BPF map — the two
// lookups every cluster workload makes.
var desyncServices = []struct{ ns, name string }{
	{"kube-system", "kube-dns"},
	{"default", "kubernetes"},
}

// serviceDesync reports whether the local BPF service map is
// currently desynced (and runs its streak + remedy); true means the
// caller must skip the nld datapath section this cycle — a desynced
// map explains any :53 failure, so the pod delete would punish the
// wrong component.
func (c *CiliumLRPCheck) serviceDesync(ctx context.Context,
	e *wdeps.CycleEnv, agentTasks []wdeps.CtrTask) bool {
	backends, err := c.d.Cfg.Seams.Cilium.ServiceBackends(ctx, c.d.Cfg.Cilium.Socket)
	if err != nil {
		// Inconclusive — the agent API hiccuped; the healthz check
		// owns the agent verdict.
		return false
	}
	var desynced []string
	for _, sv := range desyncServices {
		ready, ok := c.serviceReadyEndpoints(ctx, sv.ns, sv.name)
		if !ok {
			continue // apiserver verdict unreadable — keep, don't count
		}
		if ready > 0 && backends[sv.ns+"/"+sv.name] == 0 {
			desynced = append(desynced, sv.ns+"/"+sv.name)
		}
	}
	if len(desynced) == 0 {
		c.svcFails = 0
		return false
	}
	if c.d.StreakPending(&c.svcFails, fmt.Sprintf(
		"suspect: cilium-lrp-dns BPF service-map desync %s (ready endpoints but 0 backends)",
		strings.Join(desynced, " "))) {
		return true
	}
	if !c.d.State.RateTrySpend("last-cilium-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns BPF service-map desync %s (%dx) but agent restart in cooldown (<30m), skip",
			strings.Join(desynced, " "), c.svcFails))
		return true
	}
	// Budget spent atomically BEFORE acting (rate_spend parity).
	if killCiliumAgent(c.d, agentTasks) {
		c.d.State.AppendLog(fmt.Sprintf(latchdefs.ActionCiliumAgentKill+
			" container - BPF service-map desync %s (0 backends for ready endpoints, persisted %dx)",
			strings.Join(desynced, " "), c.svcFails))
		c.svcFails = 0
		c.d.Actions.WithLabelValues(wdeps.CheckCiliumLRP, "agent_kill").Inc()
		// This check runs after CiliumEnvoyCheck in the dispatch —
		// the shared flag won't be seen until next cycle, so bounce
		// envoy inline for the xDS resync.
		restartEnvoyAfterAgentKill(c.d, e, wdeps.CheckCiliumLRP,
			"cilium-agent restarted for BPF service-map desync")
	} else {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns BPF service-map desync %s but no live agent task to kill (kubelet retries itself)",
			strings.Join(desynced, " ")))
	}
	return true
}

// serviceReadyEndpoints counts a Service's Ready backends through
// discovery.k8s.io/v1 EndpointSlices — the source cilium-agent
// actually programs the BPF service map from (v1/Endpoints is
// deprecated on k8s ≥1.33 and can lag or be absent entirely when a
// Service is slice-native; comparing BPF state to the stale object
// false-positives the desync). ok=false means the apiserver verdict
// is unreadable — the caller keeps the streak evidence without
// counting it (the old "skip on Get error" semantics).
//
// Fallback: only when the slice LIST itself errors or returns zero
// items does the check read the legacy corev1.Endpoints object — a
// Service whose slices exist but carry only not-ready endpoints
// legitimately reports 0; that's a real verdict, not a missing one.
func (c *CiliumLRPCheck) serviceReadyEndpoints(ctx context.Context,
	ns, name string) (ready int, ok bool) {
	slices, err := c.d.Cfg.Client.DiscoveryV1().EndpointSlices(ns).
		List(ctx, metav1.ListOptions{
			LabelSelector: endpointSliceServiceLabel + "=" + name,
		})
	if err == nil && len(slices.Items) > 0 {
		for i := range slices.Items {
			for _, ep := range slices.Items[i].Endpoints {
				// nil Ready defaults true — only an explicit
				// ready=false endpoint is excluded.
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					ready++
				}
			}
		}
		return ready, true
	}
	ep, err := c.d.Cfg.Client.CoreV1().Endpoints(ns).Get(ctx, name,
		metav1.GetOptions{})
	if err != nil {
		return 0, false
	}
	for _, sub := range ep.Subsets {
		ready += len(sub.Addresses)
	}
	return ready, true
}
