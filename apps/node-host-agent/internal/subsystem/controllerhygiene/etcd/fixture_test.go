// fixture_test.go — the env wrapper binding the shared cdepstest
// fixture to a real *controllerhygiene.Hygiene. cdepstest can't
// build the Hygiene itself (importing controllerhygiene would
// cycle back into this test package), so every consuming package
// declares this same thin pair.
package etcd_test

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
	// Pin the pre-maintenance snapshot headroom gate to ample space
	// for every test: the real statfs on the host tempdir sits near
	// the 30%-of-total threshold on loaded machines and flakes any
	// test that reaches etcdguard without wireEtcdGuard's own pin.
	// Tests exercising the gate itself override Cfg.StatFSFn after
	// wiring.
	f.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	h, err := controllerhygiene.New(f.Cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(h.Deps)
	return &env{Fixture: f, H: h}
}
