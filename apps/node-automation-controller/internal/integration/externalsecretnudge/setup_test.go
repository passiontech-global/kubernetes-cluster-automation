// setup_test.go — registration coverage for the externalsecret-nudge module's
// Setup function.
package externalsecretnudge

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
	t.Setenv("EXTERNALSECRET_NUDGE_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "externalsecret-nudge", 10*time.Minute)
}

// externalsecret-nudge registers unconditionally — the flag only gates
// the tick body.
func TestSetupRegistersWhenDisabled(t *testing.T) {
	t.Setenv("EXTERNALSECRET_NUDGE_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("disabled nudge setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "externalsecret-nudge", 10*time.Minute)
}
