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
)

var ctx = context.Background()

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *probetest.Prober {
	return probetest.NewProber(cs, dyn,
		NewArgoCDAppStuckCheck,
		NewFluxHRRetriesCheck,
		NewKargoPromotionHealthCheck,
		NewFluxKustomizationHealthCheck,
		NewWorkloadScaleFlappingCheck,
		NewImagePullSecretAuditorCheck,
	)
}
