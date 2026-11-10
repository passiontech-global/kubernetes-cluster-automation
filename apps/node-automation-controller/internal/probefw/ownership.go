// ownership.go — owner-reference helpers the self-healing checks
// share:
//
//   - PodRunningReady / ReadyByOwner / ReadySiblings — the
//     healthy-sibling census every pod-delete heal gates on:
//     "someone else can absorb the traffic" must be proven before a
//     degraded pod is bounced (cloudflared tunnel, linkerd-h2 storm,
//     coredns upstream, rabbitmq quorum).
//   - OwnerGone — the kind→existence resolution the dead-owner
//     checks share (namespace-terminating wedged finalizer strip,
//     ephemeral-report GC). The linkerd protocol-stall heal resolves
//     its owner to the workload OBJECT (it patches the pod template),
//     not just existence, so it keeps its own code path.
package probefw

import (
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// PodRunningReady reports whether the pod counts toward a
// "healthy sibling" census — not deleting, Running phase, Ready
// condition true. Every sibling census below shares this predicate.
func PodRunningReady(pod *corev1.Pod) bool {
	return pod.DeletionTimestamp == nil &&
		pod.Status.Phase == corev1.PodRunning &&
		kube.PodReadyCond(pod)
}

// ReadyByOwner counts Running+Ready non-deleting pods per controller
// UID — the verbatim census the cloudflared and linkerd-h2 checks
// hand-rolled over their cluster-wide pod list. Pods with no
// controller owner land nowhere: an unowned pod cannot absorb
// another's traffic.
func ReadyByOwner(pods []corev1.Pod) map[types.UID]int {
	byOwner := map[types.UID]int{}
	for i := range pods {
		pod := &pods[i]
		if !PodRunningReady(pod) {
			continue
		}
		if ref := metav1.GetControllerOf(pod); ref != nil {
			byOwner[ref.UID]++
		}
	}
	return byOwner
}

// ReadySiblings reports how many OTHER Ready pods share pod's
// controller — byOwner minus the pod itself when it still reports
// Ready. The self-discount matters: a gray-failed pod keeps
// reporting Ready (that is what makes the failure gray), and
// counting it would let a lone replica "heal" itself while nothing
// can absorb its traffic. An unowned pod reads 0 — fail closed, no
// sibling proof.
func ReadySiblings(byOwner map[types.UID]int, pod *corev1.Pod) int {
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return 0
	}
	siblings := byOwner[ref.UID]
	// The census counts Ready pods; the degraded pod may still be
	// one of them — discount self so the guard requires a
	// GENUINELY separate sibling.
	if kube.PodReadyCond(pod) {
		siblings--
	}
	return siblings
}

// OwnerGone resolves whether the object an owner reference points at
// no longer exists — the existence probe the dead-owner checks
// share. kinds is the caller's whitelist of resolvable owner kinds
// (Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob): an
// owner of any other kind is unresolvable. Both failure shapes —
// unknown kind and lookup error — fail closed: the owner is
// presumed alive, because a dead-owner verdict gates destructive
// action (finalizer strips, orphan deletes).
//
//	gone=false, resolved=false — unresolvable; fail closed.
//	gone=true,  resolved=true  — the named object 404s.
//	gone=false, resolved=true  — the object exists (or ref is nil:
//	    "no owner" is not a dead owner).
//
// The two callers split on `resolved`: the report GC only needs the
// gone bit; the wedged-namespace check needs to tell "exists" apart
// from "unresolvable" so it can walk the ReplicaSet→Deployment chain
// for GC-pending garbage.
func OwnerGone(ctx context.Context, cs kubernetes.Interface, ns string,
	ref *metav1.OwnerReference, kinds ...string) (gone, resolved bool) {

	if ref == nil {
		return false, true
	}
	if !slices.Contains(kinds, ref.Kind) {
		return false, false
	}
	var err error
	switch ref.Kind {
	case "Pod":
		_, err = cs.CoreV1().Pods(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "Deployment":
		_, err = cs.AppsV1().Deployments(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "StatefulSet":
		_, err = cs.AppsV1().StatefulSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "DaemonSet":
		_, err = cs.AppsV1().DaemonSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "ReplicaSet":
		_, err = cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "Job":
		_, err = cs.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "CronJob":
		_, err = cs.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	default:
		return false, false // whitelisted kind with no resolver — fail closed
	}
	switch {
	case apierrors.IsNotFound(err):
		return true, true
	case err != nil:
		return false, false
	}
	return false, true
}
