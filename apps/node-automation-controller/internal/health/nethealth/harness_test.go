// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand and the testProber/testProberDyn wrappers
// binding this package's check constructors to the shared probetest
// prober (MustCheck, LedgerKeys live in probetest).
package nethealth

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

var ctx = context.Background()

func testProber(cs *fake.Clientset) *probetest.Prober {
	return testProberDyn(cs, probetest.OpDyn())
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	p := probetest.NewProber(cs, dyn,
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
	// The production sweep resolves the CILIUM_* knobs into
	// Cfg.Cilium once at Setup (probefw.CiliumConfigFromEnv —
	// clusterhealthprobes wiring); NewDeps leaves it zero, so the
	// harness stamps the documented defaults the env parse yields.
	p.Cfg.Cilium = probefw.CiliumConfig{
		BPFMapPressureThreshold: probefw.CiliumBPFMapPressureDefault,
		NodeIPAMMinFreeRatio:    probefw.CiliumNodeIPAMMinFreeDefault,
	}
	return p
}
