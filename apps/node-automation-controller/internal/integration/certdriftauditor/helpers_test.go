package certdriftauditor

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// cdaDyn builds the dynamic fake the audit's tests share — the stock
// testutil.NewDynamicClient covers every CRD in the shared table but
// NOT CustomResourceDefinition itself (the audit reads spec.conversion
// through dyn), so the CRD list kind is merged in here. Without it the
// fake panics on a List whose <Kind>List is unregistered.
func cdaDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	kinds := testutil.DynListKinds()
	kinds[customResourceDefinitionGVR] = "CustomResourceDefinitionList"
	return testutil.NewFakeDyn(kinds, objs...)
}
