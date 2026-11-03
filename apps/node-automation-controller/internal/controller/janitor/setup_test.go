// setup_test.go — registration coverage for the resource-cleanup
// janitor modules' Setup* functions.
package janitor

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
)

func TestSetupPeriodicModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name     string
		interval time.Duration
		setup    func(manager.Manager) error
	}{
		{"failed-jobs-janitor", 60 * time.Minute,
			func(m manager.Manager) error { return SetupFailedJobsJanitor(m, cs) }},
		{"evicted-pod-janitor", 10 * time.Minute,
			func(m manager.Manager) error { return SetupEvictedPodJanitor(m, cs) }},
		{"cronjob-catchup", 15 * time.Minute,
			func(m manager.Manager) error { return SetupCronJobCatchup(m, cs) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			testutil.ExpectPeriodic(t, m, tc.name, tc.interval)
		})
	}
}
