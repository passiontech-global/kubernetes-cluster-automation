package ctr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestDZShimScopeDaemonSetHostPrefix(t *testing.T) {
	f := wdepstest.New(t)
	d := ctrDeps(t, f)
	d.Cfg.CtrTaskRoot = "/host/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io"
	sid := strings.Repeat("a", 64)

	eProc := d.Proc.File(9450, "fd")
	if err := os.MkdirAll(eProc, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, d.Proc.File(9450, "stat"), "9450 (containerd-shim) D 1 0 0\n")
	if err := os.Symlink("/run/k0s/containerd/io.containerd.runtime.v2.task/k8s.io/"+sid+"/log.json (deleted)",
		filepath.Join(eProc, "9")); err != nil {
		t.Fatal(err)
	}

	ns, gotSID, ok := dzShimScope(d, 9450)
	if !ok || ns != "k8s.io" || gotSID != sid {
		t.Fatalf("dzShimScope() = (%q, %q, %v), want (%q, %q, true)", ns, gotSID, ok, "k8s.io", sid)
	}

	// Empty CtrTaskRoot must fail closed.
	d.Cfg.CtrTaskRoot = ""
	if _, _, ok := dzShimScope(&wdeps.Deps{Cfg: d.Cfg, Proc: d.Proc}, 9450); ok {
		t.Fatal("dzShimScope succeeded with empty CtrTaskRoot")
	}
}
