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

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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
	var liveUID types.UID
	switch ref.Kind {
	case "Pod":
		var o *corev1.Pod
		o, err = cs.CoreV1().Pods(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	case "Deployment":
		var o *appsv1.Deployment
		o, err = cs.AppsV1().Deployments(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	case "StatefulSet":
		var o *appsv1.StatefulSet
		o, err = cs.AppsV1().StatefulSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	case "DaemonSet":
		var o *appsv1.DaemonSet
		o, err = cs.AppsV1().DaemonSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	case "ReplicaSet":
		var o *appsv1.ReplicaSet
		o, err = cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	case "Job":
		var o *batchv1.Job
		o, err = cs.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	case "CronJob":
		var o *batchv1.CronJob
		o, err = cs.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if o != nil {
			liveUID = o.UID
		}
	default:
		return false, false // whitelisted kind with no resolver — fail closed
	}
	switch {
	case apierrors.IsNotFound(err):
		return true, true
	case err != nil:
		return false, false
	}
	// A same-name object carrying a DIFFERENT UID is a different
	// incarnation: StatefulSet pod churn and RS/Deployment rollouts
	// recreate same-name objects constantly, and the ownerRef's UID
	// points at the deleted original — the referenced owner IS gone
	// even though its name resolves. An empty ref.UID (hand-built
	// fixtures, pre-1.20 objects) or an unreadable live UID fails
	// closed: name-match alone still counts as alive.
	if ref.UID != "" && liveUID != "" && liveUID != ref.UID {
		return true, true
	}
	return false, true
}

// OwnerGone is the Deps-level twin of the package function: inside
// a sweep it resolves owners against the shared workload censuses
// first — a census HIT is authoritative (the sweep snapshot is
// fresh enough that "present" cannot be stale-gone), while a census
// MISS still falls through to the point GET because an object
// created after the census loaded would otherwise read as a false
// "owner gone" and unlock finalizer strips on a live object. Every
// kind keeps the same miss/error fallthrough: the GET is the
// authoritative answer either way.
func (d *Deps) OwnerGone(ctx context.Context, ns string,
	ref *metav1.OwnerReference, kinds ...string) (gone, resolved bool) {

	if ref != nil && slices.Contains(kinds, ref.Kind) {
		var found bool
		var liveUID types.UID
		switch ref.Kind {
		case "Pod":
			if pods, err := d.AllPods(ctx); err == nil {
				found, liveUID = censusHit(pods, ns, ref.Name,
					func(p *corev1.Pod) metav1.Object { return p })
			}
		case "ReplicaSet":
			if o, err := d.ReplicaSet(ctx, ns, ref.Name); err == nil && o != nil {
				found, liveUID = true, o.UID
			}
		case "Deployment":
			if o, err := d.Deployment(ctx, ns, ref.Name); err == nil && o != nil {
				found, liveUID = true, o.UID
			}
		case "StatefulSet":
			if o, err := d.StatefulSet(ctx, ns, ref.Name); err == nil && o != nil {
				found, liveUID = true, o.UID
			}
		case "DaemonSet":
			if o, err := d.DaemonSet(ctx, ns, ref.Name); err == nil && o != nil {
				found, liveUID = true, o.UID
			}
		case "CronJob":
			if o, err := d.CronJob(ctx, ns, ref.Name); err == nil && o != nil {
				found, liveUID = true, o.UID
			}
		case "Job":
			if o, err := d.Job(ctx, ns, ref.Name); err == nil && o != nil {
				found, liveUID = true, o.UID
			}
		}
		if found {
			// Same incarnation rule the direct GET applies: a
			// same-name object carrying a DIFFERENT UID is a
			// different incarnation — the referenced owner IS gone.
			if ref.UID != "" && liveUID != "" && liveUID != ref.UID {
				return true, true
			}
			return false, true
		}
		// Census miss or census error — could be a just-created
		// object the census predates; confirm with the
		// authoritative GET below.
	}
	return OwnerGone(ctx, d.CS, ns, ref, kinds...)
}

// censusHit scans one sweep census slice for a namespace+name match
// and returns the object's UID — the census-side twin of the point
// GET's liveUID read. found=false on no match (or empty items).
func censusHit[T any](items []T, ns, name string,
	meta func(*T) metav1.Object) (found bool, uid types.UID) {

	for i := range items {
		o := meta(&items[i])
		if o.GetNamespace() == ns && o.GetName() == name {
			return true, o.GetUID()
		}
	}
	return false, ""
}
