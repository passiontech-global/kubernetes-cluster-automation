// fixture_test.go — the env wrapper binding the shared cdepstest
// fixture to a real *controllerhygiene.Hygiene. cdepstest can't
// build the Hygiene itself (importing controllerhygiene would
// cycle back into this test package), so every consuming package
// declares this same thin pair.
package feeder_test

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
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
	// MainPID rides the shared systemd client's zero-fork read —
	// the test client is built WITHOUT exec seams so the D-Bus
	// backend never activates and every systemctl fallback routes
	// through the SAME HostExecFn seam the fixture scripts (read at
	// call time, so a test's post-New override intercepts the
	// MainPID probes exactly like the UnitProp probes it replaced).
	h.Deps.Cfg.Systemd = systemd.New(systemd.Config{HostRoot: "/",
		RunCmd: func(ctx context.Context, argv []string) (string, error) {
			return h.Deps.Cfg.HostExecFn(ctx, false, 0,
				argv[0], argv[1:]...)
		},
		RunCmdCombined: func(ctx context.Context, argv []string) (string, error) {
			return h.Deps.Cfg.HostExecFn(ctx, true, 0,
				argv[0], argv[1:]...)
		},
	})
	return &env{Fixture: f, H: h}
}
