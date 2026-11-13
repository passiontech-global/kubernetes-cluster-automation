// pods.go — the fake-clientset pod seams the typed fakes lack:
// EmulateEviction (the apiserver's pods/eviction subresource
// contract) and the PodExists presence probes shared by the eviction
// / heal module tests.
package testhelp

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// EmulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract: the fake tracker records a pods/eviction
// CREATE but never deletes the pod, so tests asserting the pod is
// gone wire the delete themselves. PDB budget enforcement stays
// apiserver-side and is stand-in'd by an explicit 429 reactor in
// refusal tests.
func EmulateEviction(cs *fake.Clientset) {
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

// PodExists reports whether a pod still exists in the fake cluster —
// any Get error (not just NotFound) reads as gone.
func PodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(t.Context(), name, metav1.GetOptions{})
	return err == nil
}

// PodExistsStrict is PodExists with a strict error contract: only
// NotFound reads as gone, any other Get failure fails the test
// instead of masquerading as an eviction.
func PodExistsStrict(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(t.Context(), name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get pod %s/%s: %v", ns, name, err)
	return false
}
