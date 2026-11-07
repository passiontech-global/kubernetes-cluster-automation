// fixture_test.go — the env wrapper binding the shared kdepstest
// fixture to a *probe.Probe (the wdepstest/cdepstest convention):
// the test files drive Cycle/RunChecks on the domain worker over a
// Deps built with the fake-exec + frozen-clock seams.
package probe

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func fixture(t *testing.T, rules []testutil.ExecRule) (*Probe, *testutil.FakeExec, string) {
	t.Helper()
	cfg, fr, dir := kdepstest.Config(t, rules)
	return New(kdepstest.Deps(t, cfg)), fr, dir
}
