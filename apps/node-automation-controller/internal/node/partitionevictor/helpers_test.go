package partitionevictor

import (
	"context"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

func peEmulateEviction(cs *fake.Clientset) {
	testutil.EmulateEviction(cs)
}
