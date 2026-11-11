// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand and the testProber/testProberDyn wrappers
// binding this package's check constructors to the shared probetest
// prober.
package liqo

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var ctx = context.Background()

// harnessChecks is this package's check roster in sweep order.
var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewLiqoTunnelHealthCheck,
}

func testProber(cs *fake.Clientset) *probetest.Prober {
	return testProberDyn(cs, nil) // nil dyn = the OpDyn default
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	// The liqo check reads networking.liqo.io Connections through dyn
	// (OpDyn seeds the list) — tests pass a seeded interface or nil.
	return probetest.NewCheckProber(cs, dyn, harnessChecks...)
}
