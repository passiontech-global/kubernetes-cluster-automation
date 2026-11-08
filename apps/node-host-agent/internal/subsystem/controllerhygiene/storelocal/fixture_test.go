// fixture_test.go — the env wrapper binding the shared cdepstest
// fixture to a real *controllerhygiene.Hygiene. cdepstest can't
// build the Hygiene itself (importing controllerhygiene would
// cycle back into this test package), so every consuming package
// declares this same thin pair.
package storelocal_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
)

type env struct {
	*cdepstest.Fixture
	H *controllerhygiene.Hygiene
}

func fixture(t *testing.T) *env {
	t.Helper()
	f := cdepstest.New(t)
	h, err := controllerhygiene.New(f.Cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(h.Deps)
	return &env{Fixture: f, H: h}
}
