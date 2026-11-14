// setup_test.go — registration coverage for the coredns-stale-watchdog module's
// Setup function.
package corednswatchdog

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
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "coredns-stale-watchdog",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "coredns-stale-watchdog", time.Minute)
}
