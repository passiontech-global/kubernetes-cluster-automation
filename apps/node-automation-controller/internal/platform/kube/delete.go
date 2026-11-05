// delete.go — the UID-preconditioned delete shape nearly every
// reaper/janitor hand-rolls: DeleteOptions{Preconditions: {UID}} —
// the "delete the object I vetted, not a same-named recreate" guard.
package kube

import (
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
