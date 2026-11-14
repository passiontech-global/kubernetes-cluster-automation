// expired_lease.go — the expired_with_running_pods shape of the
// controller-lease-guard check: the wedged-elector signature
// (spec.renewTime stale inside the wedge window while the holder's
// controller still runs pods) and its heal — bouncing the oldest
// Running pod of the holder's controller to restart the elector
// loop (split out of controller_lease_guard.go — see its header for
// the module contract and the flap/ksm shapes).
package leases

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// Expired lease + running pods — the wedged-elector signature + heal
// ---------------------------------------------------------------------------

// leaseStaleWindow reports whether the lease's renewTime is inside
// the wedge window: stale past leaseStaleMinAge but younger than
// leaseStaleMaxAge. A nil renewTime can't be judged; a lease stale
// past the max is an abandoned corpse, not a wedged elector.
func leaseStaleWindow(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.RenewTime == nil {
		return false
	}
	stale := now.Sub(lease.Spec.RenewTime.Time)
	return stale >= leaseStaleMinAge && stale < leaseStaleMaxAge
}

// controllerRunningPods returns the Running, non-terminating pods in
// pods attributable to the lease's controller: pods the holderIdentity
// names directly (client-go's "<pod>_<uuid>", kept verbatim too for
// electors that don't suffix) and pods sharing the controller owner
// UID of a resolved holder pod. Only when NO pod resolves that way —
// the holder pod already gone — does the "<lease name>-*" name-shape
// fallback run; its matches are guesses, so the second return reports
// the fallback set spanning more than one distinct controller owner
// (ownerReferences kind/name groups) and the caller must skip the
// heal this cycle.
func controllerRunningPods(lease *coordinationv1.Lease, pods []corev1.Pod) (
	targets []corev1.Pod, fallbackAmbiguous bool) {
	holderNames := map[string]bool{}
	for _, name := range kube.LeaseHolderPodCandidates(lease) {
		holderNames[name] = true
	}
	ownerUIDs := map[types.UID]bool{}
	for i := range pods {
		if !holderNames[pods[i].Name] {
			continue
		}
		if ref := metav1.GetControllerOf(&pods[i]); ref != nil {
			ownerUIDs[ref.UID] = true
		}
	}
	eligible := func(pod *corev1.Pod) bool {
		if pod.Status.Phase != corev1.PodRunning ||
			pod.DeletionTimestamp != nil {
			return false
		}
		if _, mirror := pod.Annotations["kubernetes.io/config.mirror"]; mirror {
			// Static control-plane pods (kube-controller-manager,
			// kube-scheduler) hold leader-election leases by node
			// name and match the "<lease>-*" fallback — but deleting
			// a mirror pod never restarts the static process, so it
			// is a no-op heal that would repeat every cooldown.
			return false
		}
		return true
	}
	// Pass 1 — positive attribution only: the holderIdentity-named
	// pod and its controller siblings. When ANY pod resolves this
	// way the "<lease>-*" name-shape fallback must not run at all:
	// its matches are guesses, and an expired cert-manager lease
	// also prefix-matches cert-manager-cainjector-*/
	// cert-manager-webhook-* replicas — mixing them in either
	// suppresses the heal as "ambiguous" or, worse, lets an older
	// sibling win the oldest-pod pick and get deleted instead of
	// the wedged elector.
	var out []corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if !eligible(pod) {
			continue
		}
		ref := metav1.GetControllerOf(pod)
		if holderNames[pod.Name] ||
			(ref != nil && ownerUIDs[ref.UID]) {
			out = append(out, *pod)
		}
	}
	if len(out) > 0 {
		return out, false
	}
	// Pass 2 — the holder pod is gone: fall back to the "<lease>-*"
	// name shape, grouped by controller owner so a set spanning
	// several controllers reads as ambiguous.
	fallbackOwners := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if !eligible(pod) ||
			!strings.HasPrefix(pod.Name, lease.Name+"-") {
			continue
		}
		out = append(out, *pod)
		if ref := metav1.GetControllerOf(pod); ref != nil {
			fallbackOwners[ref.Kind+"/"+ref.Name] = true
		} else {
			fallbackOwners[pod.Name] = true // unattributable — its own group
		}
	}
	return out, len(fallbackOwners) > 1
}

// healStaleLeaseController bounces the oldest Running pod of the
// stale lease's controller — restarting the holder's pod restarts
// its elector loop (and re-reads a fresh SA token), which either
// renews the lease or clears the way for a standby to take it. The
// shared pod-delete heal carries the cooldown, the maintenance-mutex
// gate and the UID precondition.
func (p *controllerLeaseGuardCheck) healStaleLeaseController(
	ctx context.Context, log logr.Logger, lease *coordinationv1.Lease,
	targets []corev1.Pod, now time.Time) {

	oldest := &targets[0]
	for i := range targets {
		if targets[i].CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = &targets[i]
		}
	}
	p.DeletePodHeal(ctx, log, CheckNameControllerLeaseGuard,
		lease.Namespace+"/"+lease.Name, oldest, leasePodHealCooldown, now)
}
