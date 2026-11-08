package certdriftauditor

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// cdaDyn builds the dynamic fake the audit's tests share — the stock
// testutil table covers every CRD the modules read but NOT
// CustomResourceDefinition itself (Check A reads spec.conversion
// through dyn), so the tests opt into the shared CRD-extended fake.
func cdaDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynWithCRDs(objs...)
}
