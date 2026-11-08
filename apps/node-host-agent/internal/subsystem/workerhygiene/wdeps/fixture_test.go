// fixture_test.go — the thin env wrapper every wdeps test file
// shares: the wdepstest fixture plus a real Hygiene built with
// workerhygiene.New so the embedded *Deps carries the wired State
// store, journal tracker and prometheus vecs the wdeps helpers need.
// Same shape the domain packages' external test files declare (see
// wdepstest's package doc).
package wdeps_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// env pairs the shared wdepstest fixture with the Hygiene it is
// bound to. D is the embedded *Deps — wdeps tests drive the wdeps
// helpers directly through it; H stays for parity with the domain
// packages' wrappers.
type env struct {
	*wdepstest.Fixture
	H *workerhygiene.Hygiene
	D *wdeps.Deps
}

// fixture builds the fixture environment, then New + Bind — the
// seams live on the *Deps copy of Cfg, so tests mutate e.D.Cfg.
func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	f := wdepstest.New(t, objs...)
	h, err := workerhygiene.New(f.Cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(h.Deps)
	return &env{Fixture: f, H: h, D: h.Deps}
}
