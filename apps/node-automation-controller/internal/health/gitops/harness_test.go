// harness_test.go — the test wiring the check tests in this package
// share: the ctx shorthand and the testProberDyn wrapper binding this
// package's check constructors to the shared probetest prober
// (MustCheck, LedgerKeys live in probetest). gitops tests always pass
// an explicit dyn, so there is no testProber shorthand.
package gitops

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

var ctx = context.Background()

// harnessChecks is this package's check roster in sweep order — the
// wrapper below passes the slice through probetest.NewCheckProber.
var harnessChecks = []func(*probefw.Deps) probefw.Check{
	NewArgoCDAppStuckCheck,
	NewFluxHRRetriesCheck,
	NewKargoPromotionHealthCheck,
	NewKedaScaledObjectGuardCheck,
	NewFluxKustomizationHealthCheck,
	NewWorkloadScaleFlappingCheck,
	NewImagePullSecretAuditorCheck,
	NewArgoCDAgentSpinCheck,
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	return probetest.NewCheckProber(cs, dyn, harnessChecks...)
}
