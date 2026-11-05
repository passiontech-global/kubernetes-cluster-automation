// mesh_controlplane_watchdog.go — the mesh-controlplane-watchdog
// check (W8-NM2/NM3): heals the Cilium operator IPAM wedge and
// wedged linkerd control-plane pods via pod deletes behind the
// shared heal cooldowns + maintenance gate.
package watchdogs

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// meshControlPlaneCheck is the W8 mesh control-plane watchdog —
// cilium-operator / linkerd control-plane pod heals.
type meshControlPlaneCheck struct{ *probefw.Deps }

// newMeshControlPlaneCheck builds the W8-NM2/NM3 watchdog —
// stateless itself; heal cooldowns ride the shared Deps.Heals
// cooldown set.
func NewMeshControlPlaneCheck(d *probefw.Deps) probefw.Check {
	return &meshControlPlaneCheck{Deps: d}
}

const (
	// W8-NM2/NM3 — mesh-controlplane-watchdog knobs.
	CheckNameMeshWatchdog = "mesh-controlplane-watchdog"
	ciliumIPAMMinAge      = 10 * time.Minute
	linkerdWedgedMinAge   = 5 * time.Minute
	ciliumOpHealCooldown  = time.Hour
	linkerdHealCooldown   = 30 * time.Minute
	ciliumOperatorNS      = "kube-system"
	ciliumOperatorPrefix  = "cilium-operator-"
	// The linkerd control-plane identifiers (namespace + the two
	// Deployment names the heal bounces) live in probefw — the
	// nethealth endpoint-sync check matches the same pods.
)

// ---------------------------------------------------------------------------
// W8-NM2/NM3 — mesh-controlplane-watchdog
// ---------------------------------------------------------------------------

// checkMeshControlPlane heals two control-plane wedge shapes:
//
//	a) W8-NM2 — any Node reporting CiliumIPAMExhausted=True >=10m:
//	   the operator's IPAM bookkeeping wedged; delete a
//	   cilium-operator-* pod (1h cooldown) so the restarted leader
//	   resyncs.
//	b) W8-NM3 — linkerd-destination/linkerd-identity pods in
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

	var findings []string

	// (a) CiliumIPAMExhausted latch.
	nodes, err := shared.ListNodes(ctx, p.CS)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	var ipamNodes []string
	for i := range nodes {
		c := shared.NodeCondition(&nodes[i], "CiliumIPAMExhausted")
		if c != nil && c.Status == corev1.ConditionTrue &&
			!c.LastTransitionTime.IsZero() &&
			now.Sub(c.LastTransitionTime.Time) >= ciliumIPAMMinAge {
			ipamNodes = append(ipamNodes, nodes[i].Name)
		}
	}
	if len(ipamNodes) > 0 {
		sort.Strings(ipamNodes)
		findings = append(findings, "cilium_ipam_exhausted:"+strings.Join(ipamNodes, ","))
		p.healComponentPod(ctx, log, "cilium-operator",
			ciliumOperatorNS, ciliumOperatorPrefix, ciliumOpHealCooldown, now)
	}

	// (b) wedged linkerd control-plane pods.
	// linkerd-destination and linkerd-identity are Deployments, so live
	// pod names carry a "<component>-<rs-hash>-<pod-hash>" suffix (or
	// the linkerd.io/control-plane-component label); exact-name match is
	// kept alongside prefix/label match for unit-test fixtures.
	if podList, err := p.CS.CoreV1().Pods(probefw.LinkerdNS).
		List(ctx, metav1.ListOptions{}); err == nil {
		for _, component := range []string{probefw.LinkerdDestinationName, probefw.LinkerdIdentityName} {
			for i := range podList.Items {
				pod := &podList.Items[i]
				if !probefw.LinkerdPodMatchesComponent(pod, component) || !linkerdPodWedged(pod, now) {
					continue
				}
				findings = append(findings, component+":wedged")
				p.healNamedPod(ctx, log, component, pod.Namespace+"/"+pod.Name,
					pod, linkerdHealCooldown, now)
				break
			}
		}
	}

	if len(findings) == 0 {
		return probefw.Result{Pass: true}
	}
	return probefw.Result{Why: "mesh control-plane wedge: " + strings.Join(findings, ", ")}
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
// generic W8-NM2 shape: same cooldown bookkeeping as every pod-delete
// heal in this sweep.
func (p *meshControlPlaneCheck) healComponentPod(ctx context.Context, log logr.Logger,
	component, ns, prefix string, cooldown time.Duration, now time.Time) {
	if p.Heals.CooledDown(component, cooldown, now) {
		log.Info("skip heal: component inside cooldown", "component", component)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"component", component, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "component", component, "why", why)
		return
	}
	pods, err := p.CS.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — heal deferred", "ns", ns, "error", err)
		return
	}
	var target *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if strings.HasPrefix(pod.Name, prefix) && pod.DeletionTimestamp == nil {
			target = pod
			break
		}
	}
	if target == nil {
		return
	}
	p.healNamedPod(ctx, log, component, target.Namespace+"/"+target.Name,
		target, cooldown, now)
}

// healNamedPod deletes the pod after the caller's cooldown decision —
// recording the ledger entry and counting the heal. The maintenance
// mutex is re-checked here (not just in healComponentPod) because
// checkMeshControlPlane calls this directly for the wedged linkerd
// pods — every pod-delete heal defers while a drain/upgrade is in
// flight, and "cannot verify" fails closed.
func (p *meshControlPlaneCheck) healNamedPod(ctx context.Context, log logr.Logger,
	component, key string, pod *corev1.Pod, cooldown time.Duration, now time.Time) {
	if p.Heals.CooledDown(component, cooldown, now) {
		log.Info("skip heal: component inside cooldown", "component", component)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"component", component, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "component", component, "why", why)
		return
	}
	uid := pod.UID
	if err := p.CS.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "control-plane pod delete failed", "pod", key)
		return
	}
	p.Heals.Stamp(component, now)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(component).Inc()
	log.Info("DELETE: wedged control-plane pod — forcing re-roll",
		"component", component, "pod", key)
}
