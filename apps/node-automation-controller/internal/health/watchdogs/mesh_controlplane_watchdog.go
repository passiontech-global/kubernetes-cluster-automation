// mesh_controlplane_watchdog.go — the mesh-controlplane-watchdog
// check (issuer-serial-watch/mesh-net-guards): heals the Cilium operator IPAM wedge and
// wedged linkerd control-plane pods via pod deletes behind the
// shared heal cooldowns + maintenance gate.
package watchdogs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// meshControlPlaneCheck is the mesh control-plane watchdog —
// cilium-operator / linkerd control-plane pod heals.
type meshControlPlaneCheck struct {
	*probefw.Deps

	// gateEvals counts HealAllowed evaluations this process made —
	// exactly one per heal attempt: healComponentPod no longer
	// pre-gates, healNamedPod is the single gate owner.
	gateEvals int
}

// newMeshControlPlaneCheck builds the issuer-serial-watch/mesh-net-guards watchdog —
// stateless itself; heal cooldowns ride the shared Deps.Heals
// cooldown set.
func NewMeshControlPlaneCheck(d *probefw.Deps) probefw.Check {
	return &meshControlPlaneCheck{Deps: d}
}

const (
	// issuer-serial-watch/mesh-net-guards — mesh-controlplane-watchdog knobs.
	CheckNameMeshWatchdog = "mesh-controlplane-watchdog"
	ciliumIPAMMinAge      = 10 * time.Minute
	linkerdWedgedMinAge   = 5 * time.Minute
	ciliumOpHealCooldown  = time.Hour
	linkerdHealCooldown   = 30 * time.Minute
	ciliumOperatorNS      = "kube-system"
	ciliumOperatorPrefix  = "cilium-operator-"
	// ciliumOperatorLease is the leader-election Lease the cilium
	// operator holds in kube-system — its spec.holderIdentity names
	// the pod owning the IPAM bookkeeping, so the heal deletes the
	// wedged LEADER instead of an arbitrary replica.
	ciliumOperatorLease        = "cilium-operator-resource-lock"
	ciliumIPAMCondHeartbeatMax = 10 * time.Minute
	// The linkerd control-plane identifiers (namespace + the two
	// Deployment names the heal bounces) live in probefw — the
	// nethealth endpoint-sync check matches the same pods.
)

// ---------------------------------------------------------------------------
// issuer-serial-watch/mesh-net-guards — mesh-controlplane-watchdog
// ---------------------------------------------------------------------------

// checkMeshControlPlane heals two control-plane wedge shapes:
//
//	a) issuer-serial-watch — any Node reporting CiliumIPAMExhausted=True >=10m:
//	   the operator's IPAM bookkeeping wedged; delete a
//	   cilium-operator-* pod (1h cooldown) so the restarted leader
//	   resyncs.
//	b) mesh-net-guards — linkerd-destination/linkerd-identity pods in
//	   namespace linkerd stuck >=5m: CrashLoopBackOff or the
//	   started-but-never-Ready wedge while the apiserver is
//	   healthy (our own client calls working proves that). Delete
//	   the pod to re-roll (30m cooldown per component).
//
// Cooldowns live in the in-RAM ledger — the heal target is the pod
// itself, nothing else can carry the stamp.
func (p *meshControlPlaneCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	var rep probefw.SweepReport

	// (a) CiliumIPAMExhausted latch.
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	var ipamNodes []string
	for i := range nodes {
		c := kube.NodeCondition(&nodes[i], "CiliumIPAMExhausted")
		// The heartbeat must be fresh: a frozen lastHeartbeatTime
		// means the reporter that owns the condition is dead — the
		// True is a zombie the node-condition-sweeper clears, not
		// live IPAM exhaustion evidence.
		if c != nil && c.Status == corev1.ConditionTrue &&
			!c.LastTransitionTime.IsZero() &&
			now.Sub(c.LastTransitionTime.Time) >= ciliumIPAMMinAge &&
			kube.CondHeartbeatLive(c, ciliumIPAMCondHeartbeatMax, now) {
			ipamNodes = append(ipamNodes, nodes[i].Name)
		}
	}
	if len(ipamNodes) > 0 {
		sort.Strings(ipamNodes)
		rep.Find("cilium_ipam_exhausted:" + strings.Join(ipamNodes, ","))
		p.healComponentPod(ctx, log, "cilium-operator",
			ciliumOperatorNS, ciliumOperatorPrefix, ciliumOpHealCooldown, now)
	}

	// (b) wedged linkerd control-plane pods.
	// linkerd-destination and linkerd-identity are Deployments, so live
	// pod names carry a "<component>-<rs-hash>-<pod-hash>" suffix (or
	// the linkerd.io/control-plane-component label); exact-name match is
	// kept alongside prefix/label match for unit-test fixtures.
	if pods, err := p.PodsIn(ctx, kube.LinkerdNS); err == nil {
		readyByOwner := probefw.ReadyByOwner(derefPods(pods))
		for _, component := range []string{kube.LinkerdDestinationName, kube.LinkerdIdentityName} {
			for i := range pods {
				pod := pods[i]
				if !probefw.LinkerdPodMatchesComponent(pod, component) || !linkerdPodWedged(pod, now) {
					continue
				}
				rep.Find(component + ":wedged")
				// A sole-replica Running-but-never-Ready pod has no
				// Ready sibling to absorb the mesh traffic while the
				// re-roll comes up: deleting it just churns replicas
				// every cooldown window while the component stays
				// degraded (the new pod starts from the same wedge).
				// Detect-only — the finding above still emits so the
				// gauge/verdict surface the wedge.
				if probefw.ReadySiblings(readyByOwner, pod) < 1 {
					log.Info("skip wedged linkerd pod: no Ready sibling replica — delete would churn a sole replica while degraded",
						"component", component, "pod", pod.Namespace+"/"+pod.Name)
					break
				}
				p.healNamedPod(ctx, log, component, pod.Namespace+"/"+pod.Name,
					pod, linkerdHealCooldown, now)
				break
			}
		}
	} else {
		// The pod list is the mesh-net-guards scan's only input — a failure
		// must count like every swallowed infra error in the heal
		// path, or a wedged linkerd control plane reads as clean
		// while the scan silently no-ops.
		metrics.IncError(p.Name)
		log.Info("WARN: list linkerd pods failed — wedge scan skipped",
			"ns", kube.LinkerdNS, "error", err)
	}

	return rep.Verdict("mesh control-plane wedge: ", ", ")
}

// derefPods copies a []*corev1.Pod census into []corev1.Pod for
// probefw.ReadyByOwner (the sibling census takes values).
func derefPods(pods []*corev1.Pod) []corev1.Pod {
	out := make([]corev1.Pod, len(pods))
	for i := range pods {
		out[i] = *pods[i]
	}
	return out
}

// linkerdPodWedged reports the wedged-watch / crashloop signature:
// the pod has been Running >= linkerdWedgedMinAge while any container
// sits in CrashLoopBackOff, or every container started but none ever
// went Ready (the ranch-style wedged-watch shape mirrored from the
// rabbitmq suspended-listener detector).
func linkerdPodWedged(pod *corev1.Pod, now time.Time) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	if now.Sub(pod.CreationTimestamp.Time) < linkerdWedgedMinAge {
		return false
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}
	allStartedNoneReady := true
	for _, s := range pod.Status.ContainerStatuses {
		if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" &&
			s.RestartCount > 2 {
			return true
		}
		if s.Started == nil || !*s.Started || s.Ready {
			allStartedNoneReady = false
		}
	}
	return allStartedNoneReady
}

// healComponentPod deletes one pod matching prefix in ns — the
// generic issuer-serial-watch shape. The cooldown/maintenance gate lives ONLY in
// healNamedPod (one HealAllowed evaluation per heal attempt — the
// old pre-gate here double-evaluated the same verdict back-to-back);
// this helper just resolves the target and hands it over.
func (p *meshControlPlaneCheck) healComponentPod(ctx context.Context, log logr.Logger,
	component, ns, prefix string, cooldown time.Duration, now time.Time) {
	pods, err := p.PodsIn(ctx, ns)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — heal deferred", "ns", ns, "error", err)
		return
	}
	var target *corev1.Pod
	if prefix == ciliumOperatorPrefix {
		target = p.ciliumOperatorLeaderPod(ctx, log, pods)
	} else {
		for i := range pods {
			pod := pods[i]
			if strings.HasPrefix(pod.Name, prefix) && pod.DeletionTimestamp == nil {
				target = pod
				break
			}
		}
	}
	if target == nil {
		return
	}
	p.healNamedPod(ctx, log, component, target.Namespace+"/"+target.Name,
		target, cooldown, now)
}

// ciliumOperatorLeaderPod resolves which cilium-operator replica the
// IPAM heal should delete: the leader-election Lease
// kube-system/cilium-operator-resource-lock's spec.holderIdentity
// names the elected holder — deleting a standby just churns a
// healthy replica while the wedged leader keeps the broken IPAM
// bookkeeping. holderIdentity is "<pod>_<uuid>" on client-go leader
// election, so the prefix-stripped name is tried before the verbatim
// identity. When the Lease is unreadable/absent or its holder does
// not match a live pod, the fallback is the first Running
// cilium-operator-* pod — still better than an arbitrary pick since
// only Running pods are re-rollable targets.
func (p *meshControlPlaneCheck) ciliumOperatorLeaderPod(ctx context.Context,
	log logr.Logger, pods []*corev1.Pod) *corev1.Pod {
	var fallback *corev1.Pod
	for i := range pods {
		pod := pods[i]
		if !strings.HasPrefix(pod.Name, ciliumOperatorPrefix) ||
			pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if fallback == nil {
			fallback = pod
		}
	}
	lease, err := p.CS.CoordinationV1().Leases(ciliumOperatorNS).
		Get(ctx, ciliumOperatorLease, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			metrics.IncError(p.Name)
			log.Info("WARN: get cilium-operator leader lease failed — first Running pod fallback",
				"lease", ciliumOperatorNS+"/"+ciliumOperatorLease, "error", err)
		}
		return fallback
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return fallback
	}
	holder := *lease.Spec.HolderIdentity
	candidates := []string{holder}
	if i := strings.LastIndex(holder, "_"); i > 0 {
		candidates = append([]string{holder[:i]}, candidates...)
	}
	for _, name := range candidates {
		for i := range pods {
			pod := pods[i]
			if pod.Name == name && pod.DeletionTimestamp == nil &&
				pod.Status.Phase == corev1.PodRunning {
				return pod
			}
		}
	}
	return fallback
}

// healNamedPod is the SOLE heal gate for this check — every pod
// delete (the generic healComponentPod target and the direct
// wedged-linkerd path) passes through exactly one HealAllowed
// evaluation here. The maintenance mutex re-check rides the shared
// Deps verdict: every pod-delete heal defers while a drain/upgrade
// is in flight, and "cannot verify" fails closed.
func (p *meshControlPlaneCheck) healNamedPod(ctx context.Context, log logr.Logger,
	component, key string, pod *corev1.Pod, cooldown time.Duration, now time.Time) {
	// A pod with no controller owner reference would NOT be recreated
	// after the delete (mirrors operator_leader_heal.go): deleting an
	// unowned control-plane pod turns a stuck component into a
	// missing one. Only a Deployment/ReplicaSet-managed pod is a safe
	// re-roll target.
	if metav1.GetControllerOf(pod) == nil {
		log.Info("skip control-plane pod heal: no controller ownerRef — nothing would re-roll the pod",
			"component", component, "pod", key)
		return
	}
	p.gateEvals++
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, component, cooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	if _, err := heal.DeletePod(ctx, p.CS, &p.Heals, component, pod, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "control-plane pod delete failed", "pod", key)
		return
	}
	p.InvalidatePods(ctx) // drop the pod census the delete just invalidated
	metrics.ControlPlanePodHealsTotal.WithLabelValues(component).Inc()
	log.Info("DELETE: wedged control-plane pod — forcing re-roll",
		"component", component, "pod", key)
}
