// helpers_test.go — shared fixtures for the whole-sweep tests: the
// sweep context, the dynamic fake (extended with the CRD list kind
// the snapshot needs), the CRD conversion fixture and the
// pods/eviction emulation.
package webhookguard

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// emulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract — same emulation shape as the unmeshed
// auditor's copy: the fake tracker records a pods/eviction CREATE
// but never deletes the pod, so tests asserting the pod is gone wire
// the delete themselves. Required since the conversion bounce evicts
// through policy/v1 (heal.EvictPod); PDB budget enforcement stays
// apiserver-side.
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

// wgDyn builds the dynamic fake the guard's tests share — the stock
// testutil table covers every CRD the modules read but NOT
// CustomResourceDefinition itself (the snapshot lists CRDs for the
// conversion-webhook checks), so the tests opt into the shared
// CRD-extended fake.
func wgDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynWithCRDs(objs...)
}

// wgCRDConversion builds a CustomResourceDefinition whose
// spec.conversion is a Webhook strategy targeting Service
// ns/name — the conversion-backend fixture.
func wgCRDConversion(crdName, svcNS, svcName string) *unstructured.Unstructured {
	crd := testutil.Unstructured(
		guardstate.CustomResourceDefinitionGVR.GroupVersion().WithKind("CustomResourceDefinition"),
		"", crdName, nil)
	_ = unstructured.SetNestedField(crd.Object, "Webhook",
		"spec", "conversion", "strategy")
	_ = unstructured.SetNestedMap(crd.Object,
		map[string]any{"namespace": svcNS, "name": svcName},
		"spec", "conversion", "webhook", "clientConfig", "service")
	return crd
}
