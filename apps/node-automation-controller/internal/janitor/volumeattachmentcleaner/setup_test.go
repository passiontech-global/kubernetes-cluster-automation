// setup_test.go — registration coverage for the volumeattachment-cleaner
// module's Setup function.
package volumeattachmentcleaner

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	t.Setenv("VOLUMEATTACHMENT_CLEANER_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "volumeattachment-cleaner", 5*time.Minute)
}

// volumeattachment-cleaner skips mgr.Add entirely when disabled
// (VOLUMEATTACHMENT_CLEANER_ENABLED=false) — same contract as
// certmanager-reaper / cilium-taint-reaper: no Periodic, no tick.
func TestSetupDisabled(t *testing.T) {
	t.Setenv("VOLUMEATTACHMENT_CLEANER_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
	}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
