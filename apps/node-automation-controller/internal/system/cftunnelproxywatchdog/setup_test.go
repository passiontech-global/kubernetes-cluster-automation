// setup_test.go — registration coverage for the cf-tunnel-proxy-watchdog
// module's Setup function.
package cftunnelproxywatchdog

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetup(t *testing.T) {
	// The CF_TUNNEL_WATCHDOG_* knobs are resolved inside Setup even
	// when Disabled is stamped (parse-knobs-before-gate ordering) —
	// pin them so a stray value in the test environment can't flake
	// the interval assertion. Zero-value Deps.Disabled = gate-on —
	// CF_TUNNEL_WATCHDOG_ENABLED is resolved by setupModules, not
	// re-read here.
	t.Setenv("CF_TUNNEL_WATCHDOG_NAMESPACE", "cloudflare-tunnel-system")
	t.Setenv("CF_TUNNEL_WATCHDOG_INTERVAL", "5m")
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "cf-tunnel-proxy-watchdog",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "cf-tunnel-proxy-watchdog", 5*time.Minute)
}
