// setup_test.go — registration coverage for the failed-jobs-janitor module's
// Setup function.
package failedjobsjanitor

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
	// dyn is only used by the buildrun-ttl-sweep BuildRun sweep — nil is fine for
	// the registration check.
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "failed-jobs-janitor",
		CS:   fake.NewSimpleClientset(),
		Dyn:  nil,
	}, "failed-jobs-janitor", 60*time.Minute)
}
