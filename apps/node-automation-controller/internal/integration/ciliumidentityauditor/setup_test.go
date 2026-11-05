// setup_test.go — registration coverage for the cilium-identity-auditor module's
// Setup function.
package ciliumidentityauditor

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
// (CILIUM_IDENTITY_AUDITOR_ENABLED is resolved by setupModules).
func TestSetupContract(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "cilium-identity-auditor",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "cilium-identity-auditor", 15*time.Minute)
}
