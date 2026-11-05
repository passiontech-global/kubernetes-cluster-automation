// setup_test.go — registration coverage for the module's Setup
// function.
package metricsserverpatcher

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add — assert exactly one runnable per Setup.
func TestSetupRegistersController(t *testing.T) {
	// Zero-value Deps.Disabled = gate-on — METRICS_SERVER_PATCHER_ENABLED
	// is resolved by setupModules, not re-read here.
	t.Setenv("METRICS_SERVER_MIN_REPLICAS", "3")
	t.Setenv("METRICS_SERVER_NODES_PER_REPLICA", "1")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "metrics-server-patcher", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The ported patcher skips mgr.Add entirely when Deps.Disabled is
// stamped.
func TestSetupDisabled(t *testing.T) {
	testutil.DisabledNoop(t, Setup, shared.Deps{
		Name: "metrics-server-patcher",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	})
}
