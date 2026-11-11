// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand and the testProber/testProberDyn wrappers
// binding this package's check constructors to the shared probetest
// prober.
package dragonfly

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var ctx = context.Background()

// harnessChecks is this package's check roster in sweep order — both
// wrappers below pass the same slice through probetest.NewCheckProber.
var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewDragonflyReplicaSyncStormCheck,
}

func testProber(cs *fake.Clientset) *probetest.Prober {
	return probetest.NewCheckProber(cs, nil, harnessChecks...)
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	return probetest.NewCheckProber(cs, dyn, harnessChecks...)
}
