// setup_test.go — registration coverage for the pdb-deadlock-watchdog
// module's Setup function.
package pdbdeadlockwatchdog

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	t.Setenv("PDB_WATCHDOG_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "pdb-deadlock-watchdog", 5*time.Minute)
}

// The watchdog skips mgr.Add entirely when disabled — no Periodic, no
// tick, no LIST against the apiserver.
func TestSetupDisabled(t *testing.T) {
	t.Setenv("PDB_WATCHDOG_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("disabled watchdog setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled watchdog registered %d runnables, want 0", len(m.Added))
	}
}
