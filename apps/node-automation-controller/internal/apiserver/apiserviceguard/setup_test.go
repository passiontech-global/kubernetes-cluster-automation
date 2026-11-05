// setup_test.go — registration coverage for the apiservice-guard
// module's Setup function.
package apiserviceguard

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names — and must
// register nothing when Deps.Disabled is stamped
// (APISERVICE_GUARD_ENABLED is resolved by setupModules).
func TestSetupContract(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "apiservice-guard",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "apiservice-guard", 5*time.Minute)
}
