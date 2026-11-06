// fixture_test.go — the env wrapper binding the shared wdepstest
// fixture to a real *workerhygiene.Hygiene. wdepstest can't build
// the Hygiene itself (importing workerhygiene would cycle back
// into this test package), so every consuming package declares
// this same thin pair.
package ctr_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

type env struct {
	*wdepstest.Fixture
	H *workerhygiene.Hygiene
}

func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	f := wdepstest.New(t, objs...)
	h, err := workerhygiene.New(f.Cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(h.Deps)
	return &env{Fixture: f, H: h}
}
