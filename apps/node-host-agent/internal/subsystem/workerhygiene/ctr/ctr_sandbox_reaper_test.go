package ctr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- cri-sandbox-reaper: orphan CRI sandbox reaper ---

// TestCtrTasksOrphanSandboxTwoPhase: a SandboxCtlRoot dir with no
// task dir and no shim gets the sandbox-orphan-seen marker on first
// observation and is removed only once the marker AND the dir
// ModTime are >=30m old — never on the first sighting.
func TestCtrTasksOrphanSandboxTwoPhase(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("7", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	if err := os.MkdirAll(sbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-31 * time.Minute)
	if err := os.Chtimes(sbDir, old, old); err != nil {
		t.Fatal(err)
	}

	e.H.Cycle(context.Background())
	// First sighting: marker only — no cleanup yet.
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("orphan sandbox removed before marker confirmation")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "sandbox-orphan-seen-"+sid)); err != nil {
		t.Fatalf("orphan-sandbox marker not written: %v", err)
	}
	// Advance past the 30m confirm window → cleanup + metric.
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background())
	if _, err := os.Stat(sbDir); !os.IsNotExist(err) {
		t.Fatal("orphan sandbox dir not removed after 30m marker")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir,
		"sandbox-orphan-seen-"+sid)); !os.IsNotExist(err) {
		t.Fatal("orphan-sandbox marker not consumed by cleanup")
	}
	if got := testutil.ToFloat64(
		e.H.Deps.Actions.WithLabelValues(wdeps.CheckCtrTasks, "rm_orphan_sandbox")); got != 1 {
		t.Fatalf("rm_orphan_sandbox=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(t), "rm orphan sandbox dir") {
		t.Fatalf("missing orphan-sandbox ACTION line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksOrphanSandboxFreshDirKept: a sandbox dir whose ModTime
// is fresh (mid-creation) must stay regardless of any stale marker.
func TestCtrTasksOrphanSandboxFreshDirKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("8", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	if err := os.MkdirAll(sbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background())
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("fresh-ModTime sandbox dir removed before its age window")
	}
}

// TestCtrTasksSandboxWithShimOrTaskKept: a sandbox dir that a live
// shim holds, or that still has a task dir under CtrTaskRoot, is
// never an orphan — even at ancient ages.
func TestCtrTasksSandboxWithShimOrTaskKept(t *testing.T) {
	e := fixture(t)
	shimSID := strings.Repeat("c", 64)
	taskSID := strings.Repeat("d", 64)
	shimDir := filepath.Join(e.SbDir, shimSID)
	taskDir := filepath.Join(e.SbDir, taskSID)
	for _, d := range []string{shimDir, taskDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		old := e.Now.Add(-2 * time.Hour)
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// Live shim scoped to OUR containerd holding shimSID.
	e.MkProc(t, 9400, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+shimSID+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// taskSID still has a task dir under CtrTaskRoot.
	if err := os.MkdirAll(filepath.Join(e.CtrDir, taskSID), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(31 * time.Minute)
	}
	if _, err := os.Stat(shimDir); err != nil {
		t.Fatal("sandbox dir with a live shim removed")
	}
	if _, err := os.Stat(taskDir); err != nil {
		t.Fatal("sandbox dir with a live task dir removed")
	}
}

// A non-hex64 dir name is not a CRI task id: the wedge scan must
// neither create a confirm marker for it nor pid-scan/SIGKILL on its
// name (the cleanup is pkill -f shaped — a dir named "kubelet" would
// otherwise spear the kubelet).
func TestCtrTasksNonHexIDNeverScanned(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.CtrDir, "kubelet")
	wdepstest.WriteFile(t, filepath.Join(dir, "garbage"), "")
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "wedged-seen-kubelet"),
		fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))
	e.H.Cycle(context.Background())
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("non-hex dir removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "wedged-seen-kubelet")); err != nil {
		t.Fatal("marker for non-hex id consumed")
	}
	if len(e.Kills) != 0 {
		t.Fatalf("SIGKILL fired for the non-hex id: %+v", e.Kills)
	}
}
