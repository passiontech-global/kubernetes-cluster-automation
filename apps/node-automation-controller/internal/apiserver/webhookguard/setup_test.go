// setup_test.go — registration coverage for the admission-webhook-guard
// module's Setup function.
package webhookguard

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names.
func TestSetupRegistersPeriodic(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "admission-webhook-guard", Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "admission-webhook-guard", 5*time.Minute)
}
