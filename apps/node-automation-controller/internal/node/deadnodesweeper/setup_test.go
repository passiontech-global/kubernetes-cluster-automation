// setup_test.go — registration coverage for the dead-node-sweeper
// module's Setup function.
package deadnodesweeper

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "dead-node-sweeper",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "dead-node-sweeper", 5*time.Minute)
}
