// helpers_test.go — the package-wide test context and the pods/eviction
// emulation the unblock-heal tests need since the heal moved to the
// policy/v1 Eviction API.
package apiserviceguard

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

var ctx = context.Background()

// emulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract — same emulation shape as the unmeshed
// auditor's copy: the fake tracker records a pods/eviction CREATE but
// never deletes the pod, so tests asserting the pod is gone wire the
// delete themselves. PDB budget enforcement stays apiserver-side and
// is stand-in'd by an explicit 429 reactor in the refusal tests.
func emulateEviction(cs *fake.Clientset) {
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
