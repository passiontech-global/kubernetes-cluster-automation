// setup_test.go — registration coverage for the apiservice-guard
// module's Setup function.
package apiserviceguard

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	// Zero-value Deps.Disabled = gate-on — APISERVICE_GUARD_ENABLED
	// is resolved by setupModules, not re-read here.
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "apiservice-guard", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "apiservice-guard", 5*time.Minute)
}

// apiservice-guard skips mgr.Add entirely when Deps.Disabled is
// stamped (setupModules resolves APISERVICE_GUARD_ENABLED) — same
// contract as cert-drift-auditor: no Periodic, no tick.
func TestSetupDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "apiservice-guard", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(), Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
