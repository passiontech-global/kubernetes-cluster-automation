// setup_test.go — registration coverage for the cronjob-catchup module's
// Setup function.
package cronjobcatchup

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
		Name: "cronjob-catchup",
		CS:   fake.NewSimpleClientset(),
	}, "cronjob-catchup", 15*time.Minute)
}
