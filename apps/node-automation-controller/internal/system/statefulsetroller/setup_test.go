// setup_test.go — registration coverage for the
// statefulset-ondelete-roller module's Setup function.
package statefulsetroller

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	t.Setenv("STATEFULSET_ONDELETE_ROLLER_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "statefulset-ondelete-roller", 10*time.Minute)
}

// The roller skips mgr.Add entirely when disabled.
func TestSetupDisabled(t *testing.T) {
	t.Setenv("STATEFULSET_ONDELETE_ROLLER_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
