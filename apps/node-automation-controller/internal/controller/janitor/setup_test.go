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
		{"volumeattachment-cleaner", 5 * time.Minute,
			func(m manager.Manager) error {
				return SetupVolumeAttachmentCleaner(m, cs, true)
			}},
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

// volumeattachment-cleaner skips mgr.Add entirely when disabled
// (VOLUMEATTACHMENT_CLEANER_ENABLED=false) — same contract as
// certmanager-reaper / cilium-taint-reaper: no Periodic, no tick.
func TestSetupVolumeAttachmentCleanerDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := SetupVolumeAttachmentCleaner(m, fake.NewSimpleClientset(), false); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
