// setup_test.go — registration coverage for the csr-watcher module's
// Setup function.
package csrwatcher

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	t.Setenv("CSR_APPROVER_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "csr-watcher", Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "csr-watcher", 10*time.Minute)
}

// csr-watcher registers unconditionally — the flag only gates the tick
// body, like the bash exit-early at the top of the hook.
func TestSetupRegistersWhenDisabled(t *testing.T) {
	t.Setenv("CSR_APPROVER_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "csr-watcher", Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("detect-only csr setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "csr-watcher", 10*time.Minute)
}
