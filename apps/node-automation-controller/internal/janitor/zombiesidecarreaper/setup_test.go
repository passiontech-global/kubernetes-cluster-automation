// setup_test.go — registration coverage for the zombie-sidecar-reaper module's
// Setup function.
package zombiesidecarreaper

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
	t.Setenv("ZOMBIE_SIDECAR_REAPER_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "zombie-sidecar-reaper", 5*time.Minute)
}

// The module skips mgr.Add entirely when disabled — same contract as
// volumeattachment-cleaner.
func TestSetupDisabled(t *testing.T) {
	t.Setenv("ZOMBIE_SIDECAR_REAPER_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(),
	}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
