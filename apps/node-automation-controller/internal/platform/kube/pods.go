// pods.go — Pod- and DaemonSet-shape helpers shared by several
// modules: the "rollout settled" verdict, the pod Ready condition
// read, and the spec container-name probe the pinned patchers rely
// on.
package kube

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// ---------------------------------------------------------------------------
// DaemonSet helpers.
// ---------------------------------------------------------------------------

// DaemonSetSettled mirrors the bash "rollout settled" check:
// observedGeneration == generation, updatedNumberScheduled ==
// desiredNumberScheduled and numberReady == desiredNumberScheduled.
func DaemonSetSettled(ds *appsv1.DaemonSet) bool {
	return ds.Status.ObservedGeneration == ds.Generation &&
		ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled &&
		ds.Status.NumberReady == ds.Status.DesiredNumberScheduled
}

// PodReadyCond reports whether the pod's Ready condition is True.
func PodReadyCond(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// PodControllerKey returns the cooldown/ledger key that survives pod
// replacement: "<ns>/<controller name>" when a controller owner
// reference exists — a "<ns>/<pod>" key is useless for workload pods
// because the recreated pod carries a fresh random suffix (Deployment
// pods get the ReplicaSet's name, which outlives every pod it
// spawns), so the re-heal of the SAME failure reads as a brand-new
// target and fires every sweep. Standalone pods fall back to
// "<ns>/<pod>" — with no controller there is no churn to key across.
func PodControllerKey(p *corev1.Pod) string {
	if ref := metav1.GetControllerOf(p); ref != nil && ref.Name != "" {
		return p.Namespace + "/" + ref.Name
	}
	return p.Namespace + "/" + p.Name
}

// PodSpecHasContainer reports whether the pod spec carries a container
// named name. The pinned patchers' strategic-merge patches merge
// containers by name and cannot create one (a name-only entry has no
// image and the apiserver rejects the pod spec), so a missing
// container must be a skip, not a patch.
func PodSpecHasContainer(ps *corev1.PodSpec, name string) bool {
	for i := range ps.Containers {
		if ps.Containers[i].Name == name {
			return true
		}
	}
	return false
}

// PodReadySince returns the pod's PodReady=True LastTransitionTime —
// the clock for stable-age fuses and "settled for >= min" gates.
// ok=false when the pod is not Ready, or the Ready condition is
// missing / carries a zero transition time — an unverifiable age is
// never treated as a settled pod (mirrors PodReadyCond, which reads
// the first PodReady-typed condition).
func PodReadySince(pod *corev1.Pod) (since time.Time, ok bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			if c.Status != corev1.ConditionTrue || c.LastTransitionTime.IsZero() {
				return time.Time{}, false
			}
			return c.LastTransitionTime.Time, true
		}
	}
	return time.Time{}, false
}

// PodUnreadyFor reports how long the pod's Ready condition has been
// non-True. Missing/zero transition time or a Ready=True condition
// both fail closed (not counted as stale-unready).
func PodUnreadyFor(pod *corev1.Pod, now time.Time) (time.Duration, bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type != corev1.PodReady {
			continue
		}
		if c.Status == corev1.ConditionTrue || c.LastTransitionTime.IsZero() {
			return 0, false
		}
		return now.Sub(c.LastTransitionTime.Time), true
	}
	return 0, false
}

// PodMergePatcher returns the patch func heal.FirstSeenPersisted /
// heal.ClearPersistedFirstSeen take when a first-seen stamp is
// carried on the pod itself: a JSON merge patch to the pod object —
// the annotation survives an operator restart that would otherwise
// re-arm an in-memory window mid-incident.
func PodMergePatcher(cs kubernetes.Interface, pod *corev1.Pod) func(context.Context, []byte) error {
	return func(ctx context.Context, data []byte) error {
		_, err := cs.CoreV1().Pods(pod.Namespace).Patch(ctx,
			pod.Name, types.MergePatchType, data, metav1.PatchOptions{})
		return err
	}
}
