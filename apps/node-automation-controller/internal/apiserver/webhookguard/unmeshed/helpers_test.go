// helpers_test.go — shared fixtures for the unmeshed auditor tests:
// the sweep context, the dynamic fake (extended with the CRD list
// kind the snapshot needs), the Service-reference builder and the
// pods/eviction emulation.
package unmeshed

import (
	"context"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// wgDyn builds the dynamic fake the auditor's tests share — the stock
// testutil.NewDynamicClient covers every CRD in the shared table but
// NOT CustomResourceDefinition itself (the snapshot lists CRDs for
// the conversion-webhook checks), so the list kind is merged in
// here. Without it the fake panics on a List whose <Kind>List is
// unregistered.
func wgDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	kinds := testutil.DynListKinds()
	kinds[guardstate.CustomResourceDefinitionGVR] = "CustomResourceDefinitionList"
	return testutil.NewFakeDyn(kinds, objs...)
}

func wgSvcRef(ns, name string) *admissionv1.ServiceReference {
	return &admissionv1.ServiceReference{Namespace: ns, Name: name}
}

// emulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract: the fake tracker records a pods/eviction
// CREATE but never deletes the pod (fixture.go only applies
// same-type subresource writes, and an Eviction is not a Pod), so
// tests asserting the pod is gone wire the delete themselves. PDB
// budget enforcement is apiserver-only and stays untested here —
// the 429-refusal path is covered by an explicit reactor instead
// (same emulation shape as the statefulset-roller's copy).
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
