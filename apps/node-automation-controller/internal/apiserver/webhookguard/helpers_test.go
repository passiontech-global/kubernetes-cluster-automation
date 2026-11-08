// helpers_test.go — shared fixtures for the whole-sweep tests: the
// sweep context, the dynamic fake (extended with the CRD list kind
// the snapshot needs) and the CRD conversion fixture.
package webhookguard

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

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
