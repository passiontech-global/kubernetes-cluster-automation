// delete.go — the UID-preconditioned delete/evict shape every
// destructive site hand-rolls: DeleteOptions{Preconditions: {UID}} —
// the "delete the object I vetted, not a same-named recreate" guard
// (apps/node-automation-controller kube.UIDDeleteOptions parity).
// Between the listing that vetted a victim and the delete, the
// object can be recreated under the same name — an unconditioned
// delete then kills an innocent replacement (or a just-scheduled
// pod), which is exactly what the UID check refuses.
package kubeutil

import (
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// UIDDeleteOptions builds DeleteOptions carrying a UID precondition:
// the apiserver rejects the delete if the live object's UID differs
// from the listed/vetted one. propagation is the desired
// DeletionPropagation policy (metav1.DeletePropagationBackground,
// ...Foreground, ...Orphan); pass "" to leave the policy unset and
// take the apiserver default.
func UIDDeleteOptions(uid types.UID, propagation metav1.DeletionPropagation) metav1.DeleteOptions {
	opts := metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}
	if propagation != "" {
		opts.PropagationPolicy = &propagation
	}
	return opts
}

// EvictPodV1 builds a policy/v1 Eviction for pod with a UID
// precondition: the apiserver refuses the eviction if the live pod's
// UID differs from the vetted one, while PodDisruptionBudget
// enforcement stays with the apiserver (the whole point of evicting
// instead of a raw delete). The precondition closes the
// listing→evict race where the same-name pod is a different object.
func EvictPodV1(pod *corev1.Pod) *policyv1.Eviction {
	opts := UIDDeleteOptions(pod.UID, "")
	return &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		DeleteOptions: &opts,
	}
}
