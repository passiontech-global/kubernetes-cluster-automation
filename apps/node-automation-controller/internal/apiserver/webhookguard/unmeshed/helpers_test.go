// helpers_test.go — shared fixtures for the unmeshed auditor tests:
// the sweep context, the dynamic fake (extended with the CRD list
// kind the snapshot needs) and the Service-reference builder. The
// pods/eviction emulation lives as testutil.EmulateEviction.
package unmeshed

import (
	"context"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
	kinds[kube.GVRCustomResourceDefinition] = "CustomResourceDefinitionList"
	return testutil.NewFakeDyn(kinds, objs...)
}

func wgSvcRef(ns, name string) *admissionv1.ServiceReference {
	return &admissionv1.ServiceReference{Namespace: ns, Name: name}
}
