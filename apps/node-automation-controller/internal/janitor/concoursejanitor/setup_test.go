// setup_test.go — registration coverage for the concourse-workdir-janitor module's
// Setup function.
package concoursejanitor

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
	// Zero-value Deps.Disabled = gate-on — the opt-in
	// CONCOURSE_JANITOR_ENABLED gate is resolved by setupModules, not
	// re-read here.
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "concourse-workdir-janitor", 30*time.Minute)
}
