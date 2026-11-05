// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand, the deps-built prober fixture
// (testProber/testProberDyn) and the mustCheck registry lookup —
// mirroring the root prober's one-instance-per-check construction so
// per-check state persists across driven runs exactly as in
// production.
package nethealth

import (
	"context"
	"testing"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

var ctx = context.Background()

// testProber is the test-side prober stand-in: the shared Deps plus
// this package's check instances built once against them.
type prober struct {
	*probefw.Deps
	checks []probefw.Check
}

func testProber(cs *fake.Clientset) *prober {
	return testProberDyn(cs, probetest.OpDyn())
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *prober {
	d := probetest.NewDeps(cs, dyn)
	return &prober{
		Deps: d,
		checks: []probefw.Check{
			NewCoreDNSUpstreamCheck(d),
			NewLinkerdEndpointSyncCheck(d),
			NewLinkerdProtocolDetectionStallCheck(d),
			NewCiliumBPFMapPressureCheck(d),
			NewCiliumNodeIPAMExhaustionCheck(d),
		},
	}
}

// mustCheck locates the registered check instance of type T — tests
// that drive one check directly or poke its state maps look the
// instance up here (exactly one check of each type is registered).
func mustCheck[T probefw.Check](t *testing.T, p *prober) T {
	t.Helper()
	for _, c := range p.checks {
		if chk, ok := c.(T); ok {
			return chk
		}
	}
	t.Fatalf("no registered check of the wanted type")
	var zero T
	return zero
}
