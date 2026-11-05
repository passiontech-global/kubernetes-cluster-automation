// setup_test.go — registration coverage for the orphan-endpointslice-cleaner module's
// Setup function.
package orphanendpointslicecleaner

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
	// Zero-value Deps.Disabled = gate-on — the registration gate
	// (ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED) is resolved by
	// setupModules, not re-read here.
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "orphan-endpointslice-cleaner",
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "orphan-endpointslice-cleaner", 15*time.Minute)
}

// The module skips mgr.Add entirely when Deps.Disabled is stamped —
// same contract as volumeattachment-cleaner.
func TestSetupDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "orphan-endpointslice-cleaner",
		Mgr:      m,
		CS:       fake.NewSimpleClientset(),
		Dyn:      testutil.StubDyn(),
		Disabled: true,
	}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
