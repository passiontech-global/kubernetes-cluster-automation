// setup_test.go — registration coverage for the
// statefulset-ondelete-roller module's Setup function.
package statefulsetroller

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The roller must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names — and must
// register nothing when Deps.Disabled is stamped (the
// STATEFULSET_ONDELETE_ROLLER_ENABLED gate is resolved by
// setupModules).
func TestSetupContract(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "statefulset-ondelete-roller",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "statefulset-ondelete-roller", 10*time.Minute)
}
