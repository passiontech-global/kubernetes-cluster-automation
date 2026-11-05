package externalsecretnudge

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// newDynFake seeds the ESO types the nudge lists — every served
// version of each GVR must carry a ListKind or the fake's List
// errors out (the production code then just tries the next GVR).
func newDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	kinds := map[schema.GroupVersionResource]string{}
	for _, gvr := range clusterSecretStoreGVRs {
		kinds[gvr] = "ClusterSecretStoreList"
	}
	for _, gvr := range secretStoreGVRs {
		kinds[gvr] = "SecretStoreList"
	}
	for _, gvr := range externalSecretGVRs {
		kinds[gvr] = "ExternalSecretList"
	}
	return testutil.NewFakeDyn(kinds, objs...)
}
