// setup_test.go — registration coverage for the cluster health
// prober's Setup* function.
package clusterhealthprobes

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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
					Name: "cluster-health-probes",
					Mgr:  m, CS: cs, Dyn: testutil.NewDynamicClient()})
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
// checker Pods were always-on, but a cluster can still opt out via
// CLUSTER_HEALTH_PROBES_ENABLED=false (setupModules evaluates the
// gate and stamps Deps.Disabled).
func TestSetupFeatureFlagVariants(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Name: "cluster-health-probes",
		Mgr:  m, CS: fake.NewSimpleClientset(), Dyn: testutil.NewDynamicClient(),
		Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

func TestSetupRunTimeoutCovers79CheckWorstCase(t *testing.T) {
	t.Setenv("CLUSTER_HEALTH_PROBES_INTERVAL", "")
	t.Setenv("HEALTH_PER_CHECK_TIMEOUT", "")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Name:      "cluster-health-probes",
		Mgr:       m,
		CS:        fake.NewSimpleClientset(),
		Dyn:       testutil.NewDynamicClient(),
		CheckRegs: fleetCheckRegs(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "cluster-health-probes", 5*time.Minute)
	p := m.Added[0].(*shared.Periodic)
	if p.RunTimeout != 29*time.Minute {
		t.Fatalf("79-check RunTimeout = %v, want 29m (14 waves * 2m + 1m)", p.RunTimeout)
	}

	mEmpty := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Name: "cluster-health-probes",
		Mgr:  mEmpty,
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.NewDynamicClient(),
	}); err != nil {
		t.Fatalf("setup empty: %v", err)
	}
	pEmpty := mEmpty.Added[0].(*shared.Periodic)
	if pEmpty.RunTimeout < 2*5*time.Minute {
		t.Fatalf("empty-roster RunTimeout = %v, want >= 10m (2*interval)", pEmpty.RunTimeout)
	}
}
