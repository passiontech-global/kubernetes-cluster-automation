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

// harnessChecks is this package's check roster in sweep order.
var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewCoreDNSUpstreamCheck,
	NewLinkerdEndpointSyncCheck,
	NewLinkerdProtocolDetectionStallCheck,
	NewCiliumBPFMapPressureCheck,
	NewCiliumNodeIPAMExhaustionCheck,
	NewCiliumMissingEndpointsCheck,
	NewLinkerdH2StreamGuardCheck,
	NewCloudflaredTunnelHealthCheck,
	NewLiqoTunnelHealthCheck,
	NewKonnectivityTunnelHealthCheck,
	NewGatewayRouteHealthCheck,
	NewEndpointSliceZoneStarvationCheck,
	NewLinkerdOutlierGuardCheck,
	NewLinkerdSidecarOOMGuardCheck,
	NewCiliumDatapathMapGuardCheck,
}

func testProber(cs *fake.Clientset) *probetest.Prober {
	return testProberDyn(cs, nil) // nil dyn = the OpDyn default
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	p := probetest.NewCheckProber(cs, dyn, harnessChecks...)
	// The production sweep resolves the CILIUM_* knobs into
	// Cfg.Cilium once at Setup (CiliumConfigFromEnv —
	// clusterhealthprobes wiring); NewDeps leaves it zero, so the
	// harness stamps the documented defaults the env parse yields.
	p.Cfg.Cilium = probefw.CiliumConfig{
		BPFMapPressureThreshold: probefw.CiliumBPFMapPressureDefault,
		NodeIPAMMinFreeRatio:    probefw.CiliumNodeIPAMMinFreeDefault,
	}
	// Same stamp for the linkerd-outlier evict kill-switch —
	// nethealth.LinkerdConfigFromEnv resolves it at Setup; tests
	// that want the gate off set the field to false directly.
	p.Cfg.Linkerd.OutlierEvictEnabled = LinkerdOutlierEvictEnabledDefault
	return p
}
