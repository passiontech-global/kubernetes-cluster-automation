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
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "partition-pod-evictor", Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "partition-pod-evictor", 5*time.Minute)
}
