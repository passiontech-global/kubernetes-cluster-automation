// setup_test.go — registration coverage for the pdb-deadlock-watchdog
// module's Setup function.
package pdbdeadlockwatchdog

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The watchdog must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names — and must
// register nothing when Deps.Disabled is stamped (PDB_WATCHDOG_ENABLED
// is resolved by setupModules).
func TestSetupContract(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "pdb-deadlock-watchdog",
		CS:   fake.NewSimpleClientset(),
	}, "pdb-deadlock-watchdog", 5*time.Minute)
}
