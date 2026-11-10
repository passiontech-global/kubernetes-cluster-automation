// ctr_internal_test.go — package-internal coverage for the
// ctrTaskInitLive liveness rule (the external ctr tests reach the
// check only through full Cycles).
package ctr

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// --- ctr_shims.go: the shim scope machinery (fail-closed) ---

func TestShimFlagValue(t *testing.T) {
	for _, tc := range []struct {
		argv  []string
		name  string
		want  string
		wantB bool
	}{
		{[]string{"shim", "-namespace", "k8s.io"}, "namespace", "k8s.io", true},
		{[]string{"shim", "--namespace", "k8s.io"}, "namespace", "k8s.io", true},
		{[]string{"shim", "-namespace=k8s.io"}, "namespace", "k8s.io", true},
		{[]string{"shim", "--namespace=k8s.io"}, "namespace", "k8s.io", true},
		{[]string{"shim", "-namespace"}, "namespace", "", false},
		{[]string{"shim", "-id", "abc"}, "namespace", "", false},
		{[]string{"shim"}, "namespace", "", false},
	} {
		got, ok := shimFlagValue(tc.argv, tc.name)
		if got != tc.want || ok != tc.wantB {
			t.Fatalf("shimFlagValue(%v,%q)=%q,%v want %q,%v",
				tc.argv, tc.name, got, ok, tc.want, tc.wantB)
		}
	}
}

func TestHostSidePath(t *testing.T) {
	for in, want := range map[string]string{
		"/host/run/k0s/containerd.sock": "/run/k0s/containerd.sock",
		"/host":                         "/",
		"/run/k0s/containerd.sock":      "/run/k0s/containerd.sock",
		"/hostile/path":                 "/hostile/path", // prefix, not the mount root
	} {
		if got := hostSidePath(in); got != want {
			t.Fatalf("hostSidePath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeCtrAddr(t *testing.T) {
	for in, want := range map[string]string{
		"unix:///run/k0s/containerd.sock":     "/run/k0s/containerd.sock",
		"unix:///var/run/k0s/containerd.sock": "/run/k0s/containerd.sock",
		"/var/run/k0s/containerd.sock":        "/run/k0s/containerd.sock",
		"/run/k0s/containerd.sock":            "/run/k0s/containerd.sock",
		"/run/k0s//containerd.sock":           "/run/k0s/containerd.sock", // Clean
		"unix://":                             "",
		"":                                    "",
	} {
		if got := normalizeCtrAddr(in); got != want {
			t.Fatalf("normalizeCtrAddr(%q)=%q want %q", in, got, want)
		}
	}
}

func TestValidShimNamespace(t *testing.T) {
	for ns, want := range map[string]bool{
		"k8s.io": true, "default": true,
		"": false, ".": false, "..": false,
		"k8s/io": false, `k8s\io`: false,
	} {
		if got := validShimNamespace(ns); got != want {
			t.Fatalf("validShimNamespace(%q)=%v want %v", ns, got, want)
		}
	}
}

func TestCtrShimScopeFailClosed(t *testing.T) {
	f := wdepstest.New(t)
	d := ctrDeps(t, f)
	id := strings.Repeat("a", 64)
	ours := []string{"containerd-shim-runc-v2", "-id", id,
		"-namespace", "k8s.io", "-address", "/run/k0s/containerd.sock"}

	// Our shim, both flags → in scope.
	ns, sid, ok := ctrShimScope(d, ours)
	if !ok || ns != "k8s.io" || sid != id {
		t.Fatalf("ctrShimScope=%q,%q,%v want k8s.io,%s,true", ns, sid, ok, id)
	}

	for name, argv := range map[string][]string{
		"no id":        {"containerd-shim-runc-v2", "-namespace", "k8s.io", "-address", "/run/k0s/containerd.sock"},
		"no namespace": {"containerd-shim-runc-v2", "-id", id, "-address", "/run/k0s/containerd.sock"},
		"no address":   {"containerd-shim-runc-v2", "-id", id, "-namespace", "k8s.io"},
		"traversal ns": {"containerd-shim-runc-v2", "-id", id, "-namespace", "..", "-address", "/run/k0s/containerd.sock"},
		"foreign addr": {"containerd-shim-runc-v2", "-id", id, "-namespace", "k8s.io", "-address", "/run/docker/containerd.sock"},
	} {
		if _, _, ok := ctrShimScope(d, argv); ok {
			t.Fatalf("%s: scope must fail closed", name)
		}
	}

	// The /var/run alias IS our socket after normalization.
	if _, _, ok := ctrShimScope(d, []string{
		"containerd-shim-runc-v2", "-id", id,
		"--namespace=k8s.io", "--address=unix:///var/run/k0s/containerd.sock"}); !ok {
		t.Fatal("the /var/run unix:// alias of our socket must be in scope")
	}
}

// --- nil-systemd / missing-input tails of the reapers ---

func TestLazyUnmountWithoutSystemdIsLogOnly(t *testing.T) {
	f := wdepstest.New(t)
	d := ctrDeps(t, f)
	d.Cfg.Systemd = nil
	dir := filepath.Join(f.CtrDir, "deadbeef"+strings.Repeat("0", 50))
	wdepstest.WriteFile(t, filepath.Join(dir, "rootfs", "bin", "sh"), "#!/bin/sh\n")
	c := &CtrTasksCheck{d: d}
	c.lazyUnmountRootfs(context.Background(), dir, "deadbeef")
	// No systemd client → log-only, no panic, best-effort removal left
	// to the caller. The suspect line is the observable.
	log := f.LogLines(t)
	if !strings.Contains(log, "no systemd client — skip umount") {
		t.Fatalf("missing nil-systemd skip line:\n%s", log)
	}
}

func TestUmountOrphanWithoutSystemdSkips(t *testing.T) {
	f := wdepstest.New(t)
	d := ctrDeps(t, f)
	d.Cfg.Systemd = nil
	c := &MountinfoCheck{d: d}
	if c.umountOrphan(context.Background(), "/run/k0s/orphan/rootfs") {
		t.Fatal("no systemd client must keep the orphan mount")
	}
	if !strings.Contains(f.LogLines(t), "no systemd client — skip umount") {
		t.Fatalf("missing nil-systemd skip line:\n%s", f.LogLines(t))
	}
}

func TestTaskDirListedEmptyRoot(t *testing.T) {
	if taskDirListed("", "abc") {
		t.Fatal("an empty task root must never list a dir")
	}
}

// TestCtrImagesLedgerSelfInit: a zero-value CtrImagesCheck (no
// ledger) initializes its exec-format ledger on the first round.
func TestCtrImagesLedgerSelfInit(t *testing.T) {
	f := wdepstest.New(t)
	d := ctrDeps(t, f)
	c := &CtrImagesCheck{d: d}
	c.Run(context.Background(), &wdeps.CycleEnv{APIOK: true, WorkerActive: true})
	if c.execFormatHealed == nil {
		t.Fatal("exec-format ledger not initialized by the first round")
	}
}
