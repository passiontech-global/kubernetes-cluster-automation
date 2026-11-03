// setup_test.go — registration coverage for the third-party
// integration unstuck modules' Setup* functions.
package integration

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
		{"helmrelease-unlocker", 10 * time.Minute,
			func(m manager.Manager) error { return SetupHelmReleaseUnlocker(m, cs, testutil.StubDyn()) }},
		{"externalsecret-nudge", 10 * time.Minute,
			func(m manager.Manager) error {
				return SetupExternalSecretNudge(m, cs, testutil.StubDyn(), true)
			}},
		{"certmanager-reaper", 15 * time.Minute,
			func(m manager.Manager) error {
				return SetupCertManagerReaper(m, cs, testutil.StubDyn(), true)
			}},
		{"cilium-identity-auditor", 15 * time.Minute,
			func(m manager.Manager) error {
				return SetupCiliumIdentityAuditor(m, cs, testutil.StubDyn(), true)
			}},
		{"cert-drift-auditor", 15 * time.Minute,
			func(m manager.Manager) error {
				return SetupCertDriftAuditor(m, cs, testutil.StubDyn(), true)
			}},
		{"velero-backup-auditor", 15 * time.Minute,
			func(m manager.Manager) error {
				return SetupVeleroBackupAuditor(m, cs, testutil.StubDyn(), true)
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

// externalsecret-nudge registers unconditionally (the flag only gates
// the tick body), while certmanager-reaper and cilium-identity-auditor
// skip mgr.Add entirely when disabled.
func TestSetupFeatureFlagVariants(t *testing.T) {
	cs := fake.NewSimpleClientset()

	m := testutil.NewStubManager()
	if err := SetupExternalSecretNudge(m, cs, testutil.StubDyn(), false); err != nil {
		t.Fatalf("disabled nudge setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "externalsecret-nudge", 10*time.Minute)

	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
	}{
		{"certmanager-reaper", func(m manager.Manager) error {
			return SetupCertManagerReaper(m, cs, testutil.StubDyn(), false)
		}},
		{"cilium-identity-auditor", func(m manager.Manager) error {
			return SetupCiliumIdentityAuditor(m, cs, testutil.StubDyn(), false)
		}},
		{"cert-drift-auditor", func(m manager.Manager) error {
			return SetupCertDriftAuditor(m, cs, testutil.StubDyn(), false)
		}},
		{"velero-backup-auditor", func(m manager.Manager) error {
			return SetupVeleroBackupAuditor(m, cs, testutil.StubDyn(), false)
		}},
	} {
		t.Run(tc.name+"-disabled", func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("disabled setup must return nil, got %v", err)
			}
			if len(m.Added) != 0 {
				t.Fatalf("disabled module registered %d runnables, want 0",
					len(m.Added))
			}
		})
	}
}
