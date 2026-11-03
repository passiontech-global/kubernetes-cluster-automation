// setup_test.go — registration coverage for the cf-tunnel-proxy-watchdog
// module's Setup function.
package cftunnelproxywatchdog

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersPeriodic(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), true,
		"cloudflare-tunnel-system", 5*time.Minute); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "cf-tunnel-proxy-watchdog", 5*time.Minute)
}

// The ported watchdog skips mgr.Add entirely when disabled.
func TestSetupDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), false,
		"cloudflare-tunnel-system", 5*time.Minute); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}
