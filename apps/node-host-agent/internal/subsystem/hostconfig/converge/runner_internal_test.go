// runner_internal_test.go — parity pins for the hostexec adapters.
// The no-stack-timeout policy is load-bearing: RunBudget owns the
// per-command deadline (applying the budget to ctx before the runner
// sees it), and hostexec would otherwise arm its own 30s default —
// silently clipping deliberate remediation budgets (the apiserver
// wedge gate's `timeout 90 systemctl restart`). A regression back to
// a real Timeout passes every seam-replaced test, so pin the adapter
// configs directly (reflect read: hostexec.cfg is unexported and the
// adapters are package vars, so there is no accessor by design).
package converge

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
)

// adapterTimeout reads hostexec.Runner's unexported cfg.Timeout.
func adapterTimeout(t *testing.T, r *hostexec.Runner) time.Duration {
	t.Helper()
	cfg := reflect.ValueOf(r).Elem().FieldByName("cfg")
	if !cfg.IsValid() {
		t.Fatal("hostexec.Runner.cfg field renamed — retarget this pin")
	}
	to := cfg.FieldByName("Timeout")
	if !to.IsValid() || to.Kind() != reflect.Int64 {
		t.Fatal("hostexec.Config.Timeout field renamed — retarget this pin")
	}
	return time.Duration(to.Int()) // Int: Interface() panics on unexported fields
}

func TestAdaptersDoNotStackTimeout(t *testing.T) {
	for name, r := range map[string]*hostexec.Runner{
		"nsenter": nsenterAdapt,
		"direct":  directAdapt,
	} {
		if got := adapterTimeout(t, r); got != noStackTimeout {
			t.Fatalf("%s adapter Timeout = %v, want the inert noStackTimeout sentinel", name, got)
		}
	}
	if noStackTimeout != time.Duration(math.MaxInt64) {
		t.Fatalf("noStackTimeout is no longer the inert sentinel: %v", noStackTimeout)
	}
}
