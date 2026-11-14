// setup_test.go — registration coverage for the partition-pod-evictor
// module's Setup function.
package partitionevictor

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "partition-pod-evictor",
		CS:   fake.NewSimpleClientset(),
	}, "partition-pod-evictor", 5*time.Minute)
}
