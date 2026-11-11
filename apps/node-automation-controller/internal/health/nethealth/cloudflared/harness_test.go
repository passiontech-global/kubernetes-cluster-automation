// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand and the testProber wrapper binding this
// package's check constructors to the shared probetest prober.
package cloudflared

import (
	"context"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var ctx = context.Background()

// harnessChecks is this package's check roster in sweep order.
var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewCloudflaredTunnelHealthCheck,
}

func testProber(cs *fake.Clientset) *probetest.Prober {
	// nil dyn = the OpDyn default — the cloudflared check scopes its
	// evidence to pod listings, :2000/metrics scrapes and kubelet log
	// tails, none of which need the dynamic client.
	return probetest.NewCheckProber(cs, nil, harnessChecks...)
}
