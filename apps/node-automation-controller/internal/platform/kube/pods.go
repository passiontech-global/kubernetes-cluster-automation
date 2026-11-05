// pods.go — Pod- and DaemonSet-shape helpers shared by several
// modules: the "rollout settled" verdict, the pod Ready condition
// read, and the spec container-name probe the pinned patchers rely
// on.
package kube

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
