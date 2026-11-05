// setup_test.go — registration coverage for the volumeattachment-cleaner
// module's Setup function.
package volumeattachmentcleaner

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names — and must
// register nothing when Deps.Disabled is stamped
// (VOLUMEATTACHMENT_CLEANER_ENABLED is resolved by setupModules).
func TestSetupContract(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "volumeattachment-cleaner",
		CS:   fake.NewSimpleClientset(),
	}, "volumeattachment-cleaner", 5*time.Minute)
}
