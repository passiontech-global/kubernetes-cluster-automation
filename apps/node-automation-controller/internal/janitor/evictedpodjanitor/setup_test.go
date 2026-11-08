// setup_test.go — registration coverage for the evicted-pod-janitor module's
// Setup function.
package evictedpodjanitor

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
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "evicted-pod-janitor",
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "evicted-pod-janitor", 10*time.Minute)
}

// A disabled module (GateEnv off → Deps.Disabled) must register
// nothing — the gate rides shared.SetupNoConfig like every module.
func TestSetupDisabledRegistersNothing(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "evicted-pod-janitor",
		Mgr:      m,
		CS:       fake.NewSimpleClientset(),
		Disabled: true,
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables", len(m.Added))
	}
}
