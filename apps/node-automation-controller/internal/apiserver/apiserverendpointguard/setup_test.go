// setup_test.go — registration coverage for the apiserver-endpoint-guard
// module's Setup function.
package apiserverendpointguard

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The endpoint guard is a plain Runnable (not AddPeriodic) — assert
// its constructor wiring survived: probe seam, backends streak map.
func TestSetup(t *testing.T) {
	cs := fake.NewSimpleClientset()
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "apiserver-endpoint-guard", Mgr: m, CS: cs, Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("expected 1 runnable, got %d", len(m.Added))
	}
	g, ok := m.Added[0].(*apiServerEndpointGuard)
	if !ok {
		t.Fatalf("runnable is %T, want *apiServerEndpointGuard", m.Added[0])
	}
	if g.backends == nil {
		t.Fatal("backends streak map not initialized")
	}
	if g.probeFn == nil {
		t.Fatal("probeFn seam not wired to g.probe")
	}
	if headroom := endpointGuardRunTimeout - endpointGuardProbeBudget; headroom < 15*time.Second {
		t.Fatalf("endpointGuardRunTimeout (%s) - endpointGuardProbeBudget (%s) = %s, want >= 15s",
			endpointGuardRunTimeout, endpointGuardProbeBudget, headroom)
	}
}
