// harness_test.go — test wiring for the connectionskew check package.
package connectionskew

import (
	"context"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var ctx = context.Background()

var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewWorkloadConnectionSkewGuardCheck,
}

func testProber(cs *fake.Clientset) *probetest.Prober {
	return probetest.NewCheckProber(cs, nil, harnessChecks...)
}
