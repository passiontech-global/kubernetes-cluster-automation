// setup_test.go — registration coverage for the cluster health
// prober's Setup* function.
package clusterhealthprobes

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupPeriodicModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name     string
		interval time.Duration
		setup    func(*testutil.StubManager) error
	}{
		{"cluster-health-probes", 5 * time.Minute,
			func(m *testutil.StubManager) error {
				return Setup(shared.Deps{
					Mgr: m, CS: cs, Dyn: testutil.NewFakeDyn(nil)})
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// cluster-health-probes resolves its interval from env at
			// Setup — pin it so a stray CLUSTER_HEALTH_PROBES_INTERVAL
			// in the test environment can't flake the assertion.
			t.Setenv("CLUSTER_HEALTH_PROBES_INTERVAL", "")
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			testutil.ExpectPeriodic(t, m, tc.name, tc.interval)
		})
	}
}

// The prober skips mgr.Add entirely when disabled — the kuberhealthy
// checker Pods were always-on, but a cluster can still opt out.
func TestSetupFeatureFlagVariants(t *testing.T) {
	t.Setenv("CLUSTER_HEALTH_PROBES_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Mgr: m, CS: fake.NewSimpleClientset(), Dyn: testutil.NewFakeDyn(nil)}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
