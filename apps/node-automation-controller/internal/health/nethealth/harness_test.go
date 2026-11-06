// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand and the testProber/testProberDyn wrappers
// binding this package's check constructors to the shared probetest
// prober (MustCheck, LedgerKeys live in probetest).
package nethealth

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

var ctx = context.Background()

func testProber(cs *fake.Clientset) *probetest.Prober {
	return testProberDyn(cs, probetest.OpDyn())
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	return probetest.NewProber(cs, dyn,
		NewCoreDNSUpstreamCheck,
		NewLinkerdEndpointSyncCheck,
		NewLinkerdProtocolDetectionStallCheck,
		NewCiliumBPFMapPressureCheck,
		NewCiliumNodeIPAMExhaustionCheck,
		NewCiliumMissingEndpointsCheck,
		NewLinkerdH2StreamGuardCheck,
		NewCloudflaredTunnelHealthCheck,
		NewLiqoTunnelHealthCheck,
	)
}
