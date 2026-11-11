// harness_test.go — the test wiring the linkerd check tests share:
// the ctx shorthand and the testProber/testProberDyn wrappers binding
// the package's five check constructors to the shared probetest
// prober (MustCheck, LedgerKeys live in probetest).
package linkerd

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var ctx = context.Background()

// harnessChecks is the linkerd check roster in sweep order.
var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewLinkerdEndpointSyncCheck,
	NewLinkerdProtocolDetectionStallCheck,
	NewLinkerdH2StreamGuardCheck,
	NewLinkerdOutlierGuardCheck,
	NewLinkerdSidecarOOMGuardCheck,
}

func testProber(cs *fake.Clientset) *probetest.Prober {
	return testProberDyn(cs, nil) // nil dyn = the OpDyn default
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	return probetest.NewCheckProber(cs, dyn, harnessChecks...)
}
