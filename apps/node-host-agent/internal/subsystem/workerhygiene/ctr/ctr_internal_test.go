// ctr_internal_test.go — package-internal coverage for the
// ctrTaskInitLive liveness rule (the external ctr tests reach the
// check only through full Cycles).
package ctr

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// ctrDeps builds a minimal *wdeps.Deps over the shared fixture —
// the same construction workerhygiene.New does, minus the parent
// package (importing it here would cycle).
func ctrDeps(t *testing.T, f *wdepstest.Fixture) *wdeps.Deps {
	t.Helper()
	cfg := f.Cfg
	cfg.ApplyDefaults()
	d := &wdeps.Deps{
		Cfg:  cfg,
		Proc: procfs.New(cfg.ProcRoot),
		State: subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
			cfg.Seams.Host.Clock,
			func() *slog.Logger {
				return slog.New(slog.NewTextHandler(io.Discard, nil))
			}),
	}
	d.Cycles, d.Actions = subframe.Counters("ctr-test",
		"test cycles", "test actions")
	f.Bind(d)
	return d
}

func TestCtrTaskInitLive(t *testing.T) {
	f := wdepstest.New(t)
	d := ctrDeps(t, f)
	dir := filepath.Join(f.CtrDir, "k8s.io", "abc123")

	// Missing init.pid → not live.
	if ctrTaskInitLive(d, dir) {
		t.Fatal("missing init.pid must report not live")
	}

	// Garbage pid → not live.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.pid"), []byte("zero\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ctrTaskInitLive(d, dir) {
		t.Fatal("garbage init.pid must report not live")
	}

	// Live pid (killFn(0) answers nil, /proc stat non-Z) → live.
	f.Live[42] = true
	pdir := filepath.Join(f.ProcDir, "42")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "stat"),
		[]byte("42 (conmon) S 1 0 0 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.pid"),
		[]byte(strconv.Itoa(42)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ctrTaskInitLive(d, dir) {
		t.Fatal("live init pid must report live")
	}

	// Zombie pid → not live.
	if err := os.WriteFile(filepath.Join(pdir, "stat"),
		[]byte("42 (conmon) Z 1 0 0 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ctrTaskInitLive(d, dir) {
		t.Fatal("zombie init pid must report not live")
	}

	// Dead pid (ESRCH) → not live.
	f.Live[42] = false
	if ctrTaskInitLive(d, dir) {
		t.Fatal("dead init pid must report not live")
	}
}
