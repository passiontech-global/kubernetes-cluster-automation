// setup_test.go — registration coverage for the failed-jobs-janitor module's
// Setup function.
package failedjobsjanitor

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names.
func TestSetupRegistersPeriodic(t *testing.T) {
	m := testutil.NewStubManager()
	// dyn is only used by the W9-GO2 BuildRun sweep — nil is fine for
	// the registration check.
	if err := Setup(shared.Deps{Name: "failed-jobs-janitor",
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: nil,
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "failed-jobs-janitor", 60*time.Minute)
}
