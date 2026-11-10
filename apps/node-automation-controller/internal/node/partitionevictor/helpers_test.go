package partitionevictor

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

var ctx = context.Background()

// peEmulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract — same emulation shape as the sibling
// packages' copies: the fake tracker records a pods/eviction CREATE
// but never deletes the pod (it only applies same-type subresource
// writes, and an Eviction is not a Pod), so tests asserting the pod
// is gone wire the delete themselves. PDB budget enforcement stays
// apiserver-side and is stand-in'd by an explicit 429 reactor in the
// refusal test.
func peEmulateEviction(cs *fake.Clientset) {
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil // a real pod create — let the tracker take it
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			return true, ev, cs.Tracker().Delete(
				corev1.SchemeGroupVersion.WithResource("pods"),
				ca.GetNamespace(), ev.Name)
		})
}
