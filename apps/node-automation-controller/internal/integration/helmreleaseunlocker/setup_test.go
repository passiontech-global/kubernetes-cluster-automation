// setup_test.go — registration coverage for the helmrelease-unlocker module's
// Setup function.
package helmreleaseunlocker

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names.
func TestSetupRegistersPeriodic(t *testing.T) {
	t.Setenv("HELM_STALL_UNWEDGE_ENABLED", "true")
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "helmrelease-unlocker",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "helmrelease-unlocker", 10*time.Minute)
}
