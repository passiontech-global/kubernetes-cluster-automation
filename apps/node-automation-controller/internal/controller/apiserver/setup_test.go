// setup_test.go — registration coverage for the apiserver-integrity
// modules' Setup* functions.
package apiserver

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
)

func TestSetupPeriodicModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name     string
		interval time.Duration
		setup    func(manager.Manager) error
	}{
		{"admission-webhook-guard", 5 * time.Minute,
			func(m manager.Manager) error { return SetupWebhookGuard(m, cs) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			testutil.ExpectPeriodic(t, m, tc.name, tc.interval)
		})
	}
}

// The endpoint guard is a plain Runnable (not AddPeriodic) — assert
// its constructor wiring survived: probe seam, backends streak map.
func TestSetupAPIServerEndpointGuard(t *testing.T) {
	cs := fake.NewSimpleClientset()
	m := testutil.NewStubManager()
	if err := SetupAPIServerEndpointGuard(m, cs); err != nil {
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
}
