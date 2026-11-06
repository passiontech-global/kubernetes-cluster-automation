// setup_test.go — registration coverage for the externalsecret-nudge module's
// Setup function.
package externalsecretnudge

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
// (EXTERNALSECRET_NUDGE_ENABLED is a REGISTRATION gate resolved by
// setupModules, not a run-time flag the tick checks).
func TestSetupContract(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "externalsecret-nudge",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "externalsecret-nudge", 10*time.Minute)
}
