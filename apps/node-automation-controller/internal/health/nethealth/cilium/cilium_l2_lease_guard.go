// cilium_l2_lease_guard.go — the cilium-l2-lease-guard check
// (cilium-l2-lease-guard): the cilium-agent leader for a Service's L2 announcement
// holds the Lease cilium-l2announce-<svc>_<ns> in kube-system; when
// that holder is a node that cannot actually answer ARP on the VIP
// segment — the node is gone, NotReady, reports
// NetworkUnavailable=True, is cordoned (unschedulable), carries the
// control-plane role (the L2 policy's nodeSelector excludes it —
// cilium-l2-lease-guard's static Rule 9), or its cilium-agent pod has been
// not-Ready for >= 2 consecutive sweep cycles — the VIP keeps being
// announced from a blackhole: every route backend behind it reads
// zero Ready endpoints exactly like gateway-route-health's
// backend_zero_endpoints signature (the two checks share the
// VIP-blackhole observation from opposite ends).
//
// Each stale signature sets
// node_automation_cilium_l2_stale_lease{lease,holder,reason} = 1 and,
// through the shared heal gate (10m cooldown per lease, maintenance
// mutex fail-closed), DELETES the Lease so Cilium re-elects a healthy
// holder immediately instead of waiting out the holdTime.
package cilium

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// ciliumL2LeaseGuardCheck is the cilium L2 announcement Lease
// watchdog.
type ciliumL2LeaseGuardCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale
	// 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// agentNotReadyStreak counts consecutive sweep cycles each node's
	// cilium-agent pod read not-Ready; the cilium_agent_not_ready
	// reason fires at >= 2 — one not-Ready sweep is an agent restart
	// blip, two in a row is the agent down. A Ready sweep resets the
	// streak (not-consecutive cycles are restarts, not an outage), so
	// a later flap re-arms it.
	agentNotReadyStreak map[string]int
}

// NewCiliumL2LeaseGuardCheck builds the cilium-l2-lease-guard check — the gauge
// ledger and the streak map are zero-value ready; heal cooldowns
// ride the shared Deps.Heals set.
func NewCiliumL2LeaseGuardCheck(d *probefw.Deps) probefw.Check {
	return &ciliumL2LeaseGuardCheck{Deps: d,
		agentNotReadyStreak: map[string]int{}}
}

const (
	CheckNameCiliumL2LeaseGuard = "cilium-l2-lease-guard"

	// cilium-l2-lease-guard — cilium-l2-lease-guard knobs.
	// ciliumL2LeaseHealCool is the per-lease delete cooldown — the
	// Cilium agent re-elects within seconds of losing the Lease, so
	// ten minutes means the heal either worked or the cluster has a
	// deeper agent problem the gauge already flags.
	ciliumL2LeaseHealCool = 10 * time.Minute
	// ciliumAgentNotReadyStreak is how many consecutive not-Ready
	// sweeps the holder's cilium-agent must read before the Lease
	// counts as stale.
	ciliumAgentNotReadyStreak = 2
	// ciliumL2LeasePrefix is the leader-election Lease name prefix
	// the cilium-agent L2 announcement loop owns in kube-system.
	ciliumL2LeasePrefix = "cilium-l2announce-"
)

// The reason values node_automation_cilium_l2_stale_lease carries —
// one per stale-holder class the check flags.
const (
	l2ReasonNodeMissing   = "node_missing"
	l2ReasonNodeNotReady  = "node_not_ready"
	l2ReasonNetUnavail    = "network_unavailable"
	l2ReasonUnschedulable = "node_unschedulable"
	l2ReasonTainted       = "node_remediation_tainted"
	l2ReasonControlPlane  = "control_plane_node"
	l2ReasonAgentNotReady = "cilium_agent_not_ready"

	// The node shapes the predicate reads.
	l2ControlPlaneRoleLabel = "node-role.kubernetes.io/control-plane"
)

var (
	// cilium-l2-lease-guard — one series per (lease, holder, stale reason).
	ciliumL2StaleLeaseGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_l2_stale_lease",
		Help: "1 while a cilium-l2announce Lease's holder cannot answer the VIP segment (node_missing, node_not_ready, network_unavailable, node_unschedulable, control_plane_node, cilium_agent_not_ready) — the check deletes the Lease under the heal gate so Cilium re-elects.",
	}, []string{"lease", "holder", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ciliumL2StaleLeaseGauge)
}

// ---------------------------------------------------------------------------
// the sweep
// ---------------------------------------------------------------------------

// checkCiliumL2LeaseGuard sweeps the kube-system cilium-l2announce-*
// Leases, scores each holder against the node census + the
// cilium-agent readiness streak, flags every stale reason on the
// gauge, then deletes each stale Lease under the shared heal gate.
func (p *ciliumL2LeaseGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// The memoized cluster-wide lease census filtered to kube-system
	// replaces the dedicated LIST — one paged read per sweep shared
	// with every other lease consumer.
	allLeases, err := p.AllLeases(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list leases: %w", err)}
	}
	var leases []coordinationv1.Lease
	for i := range allLeases {
		if allLeases[i].Namespace == "kube-system" {
			leases = append(leases, allLeases[i])
		}
	}
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	byName := map[string]*corev1.Node{}
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
	}
	agentNotReady := p.ciliumAgentStreak(ctx, nodes)

	var rep probefw.SweepReport
	for i := range leases {
		lease := &leases[i]
		if !strings.HasPrefix(lease.Name, ciliumL2LeasePrefix) {
			continue
		}
		holder := derefString(lease.Spec.HolderIdentity)
		reasons := ciliumL2StaleHolderReasons(lease, byName[holder],
			agentNotReady[holder] >= ciliumAgentNotReadyStreak)
		if len(reasons) == 0 {
			continue
		}
		for _, reason := range reasons {
			key := lease.Name + "/" + holder + "/" + reason
			rep.Emit(ciliumL2StaleLeaseGauge, key,
				[]string{lease.Name, holder, reason},
				fmt.Sprintf("%s holder=%s (%s)", lease.Name, holder, reason))
		}
		p.deleteStaleLease(ctx, log, lease, now)
	}
	return rep.Result(&p.emitted, ciliumL2StaleLeaseGauge.DeleteLabelValues,
		"cilium L2 announce leases with stale holders: ", ", ")
}

// ciliumL2StaleHolderReasons is the stale-holder predicate matrix:
// every reason the holder fails, empty when the holder is healthy
// (node exists, Ready, network available, schedulable,
// non-control-plane, cilium-agent Ready two consecutive sweeps).
// Pure — the unit tests cover each reason.
func ciliumL2StaleHolderReasons(lease *coordinationv1.Lease,
	node *corev1.Node, agentNotReady bool) []string {

	var reasons []string
	if node == nil {
		// A gone holder — or an empty holderIdentity, which is no
		// holder at all — reads the same blackhole class: nobody
		// answers the ARP.
		return []string{l2ReasonNodeMissing}
	}
	if !nodeReady(node) {
		reasons = append(reasons, l2ReasonNodeNotReady)
	}
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeNetworkUnavailable &&
			c.Status == corev1.ConditionTrue {
			reasons = append(reasons, l2ReasonNetUnavail)
			break
		}
	}
	if node.Spec.Unschedulable {
		reasons = append(reasons, l2ReasonUnschedulable)
	}
	// remediation-taint-detect: a remediation/out-of-service TAINT flags the holder as
	// stale even when spec.Unschedulable is false — cordon alone does
	// not always precede a fence, and a partitioned/stealing node
	// still answers L2 announcements while pods are being evicted.
	if kube.HasRemediationOrOutOfServiceTaint(node) {
		reasons = append(reasons, l2ReasonTainted)
	}
	if _, cp := node.Labels[l2ControlPlaneRoleLabel]; cp {
		// The L2 announcement policy's nodeSelector excludes
		// control-plane nodes (cilium-l2-lease-guard Rule 9) — a holder carrying
		// the role announces a VIP no policy-selected agent answers.
		reasons = append(reasons, l2ReasonControlPlane)
	}
	if agentNotReady {
		reasons = append(reasons, l2ReasonAgentNotReady)
	}
	return reasons
}

// nodeReady reports the node's Ready condition True (absent
// condition reads not-Ready — a node that never reported Ready is
// the same blackhole).
func nodeReady(node *corev1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ciliumAgentStreak updates and returns the per-node cilium-agent
// not-Ready streak: one pod's not-Ready sweep increments, a Ready
// sweep resets. A pod-list failure leaves the streak untouched —
// "can't tell" must not count as a not-Ready cycle. A node whose
// agent pod has vanished (pod deleted, node fine) does NOT
// accumulate — Cilium not scheduling an agent is the operator's
// problem, not a stale lease, and the node-level reasons already
// cover a gone node.
func (p *ciliumL2LeaseGuardCheck) ciliumAgentStreak(
	ctx context.Context, nodes []corev1.Node) map[string]int {

	pods, err := p.AllPods(ctx)
	if err != nil {
		return p.agentNotReadyStreak
	}
	onNode := map[string]bool{}
	for i := range nodes {
		onNode[nodes[i].Name] = true
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != "kube-system" ||
			pod.Spec.NodeName == "" || !onNode[pod.Spec.NodeName] {
			continue
		}
		// The agent pod is the DaemonSet pod — `k8s-app=cilium`
		// (upstream helm) or a `cilium-*` name on installs that drop
		// the label. `cilium-operator-*` shares the name prefix but
		// is a DIFFERENT workload: its not-Ready window during an
		// operator restart/upgrade must not poison the per-node
		// agent streak into deleting a healthy holder's lease.
		agent := pod.Labels["k8s-app"] == "cilium" ||
			(strings.HasPrefix(pod.Name, "cilium-") &&
				!strings.HasPrefix(pod.Name, "cilium-operator-"))
		if !agent || pod.DeletionTimestamp != nil {
			continue
		}
		if podReadyStatus(pod) {
			delete(p.agentNotReadyStreak, pod.Spec.NodeName)
			continue
		}
		p.agentNotReadyStreak[pod.Spec.NodeName]++
	}
	// A node that vanished while not-Ready is never revisited — its
	// agent pod is gone with it, so the loop above can neither reset
	// nor delete the key. Prune against the live node census (the
	// same caller-prune contract every state ledger carries) so the
	// map stays bounded by cluster size.
	for node := range p.agentNotReadyStreak {
		if !onNode[node] {
			delete(p.agentNotReadyStreak, node)
		}
	}
	return p.agentNotReadyStreak
}

// deleteStaleLease deletes one stale Lease through the shared heal
// gate — per-lease 10m cooldown on Deps.Heals, maintenance mutex
// fail-closed — with a UID precondition so a re-elected holder's
// fresh Lease is never the delete target. The stamp lands only on a
// delivered delete, mirroring heal.DeletePod's contract.
func (p *ciliumL2LeaseGuardCheck) deleteStaleLease(
	ctx context.Context, log logr.Logger, lease *coordinationv1.Lease,
	now time.Time) {

	key := probefw.SelfHealKey(CheckNameCiliumL2LeaseGuard,
		"lease/"+lease.Name)
	proceed, unverifiable := p.HealAllowed(ctx, log, &p.Heals, key,
		ciliumL2LeaseHealCool, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	err := p.CS.CoordinationV1().Leases(lease.Namespace).Delete(ctx,
		lease.Name, kube.UIDDeleteOptions(lease.UID,
			metav1.DeletePropagationBackground))
	switch {
	case apierrors.IsNotFound(err):
		// Another actor (the Cilium agent itself) beat us to it —
		// the stale holder is gone either way.
		p.Heals.Stamp(key, now)
	case err != nil:
		log.Info("WARN: stale cilium L2 announce lease delete failed",
			"lease", lease.Name, "error", err)
	default:
		p.Heals.Stamp(key, now)
		log.Info("HEAL: deleted stale cilium L2 announce lease — re-elect a healthy holder",
			"lease", lease.Name,
			"holder", derefString(lease.Spec.HolderIdentity))
	}
}

// podReadyStatus reports the pod's Ready condition True.
func podReadyStatus(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// derefString renders a nilable string field for logs/labels.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
