// ctr_nil_once_test.go — regression coverage for hand-built CycleEnv
// calls with PidsOnce == nil in ctr-tasks, verifying Proc.PIDs()
// fallback and fail-closed inconclusive abort when /proc is unreadable.
package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCtrTasksNilPidsOnceFallsBackAndAbortsOnProcError(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	chk := e.H.Check(wdeps.CheckCtrTasks)

	// Hand-built CycleEnv with PidsOnce == nil and valid ProcRoot -> falls back to Proc.PIDs().
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1", got)
	}

	// Unreadable /proc must abort inconclusive and preserve markers + latch holds.
	marker := "wedged-seen-" + strings.Repeat("a", 64)
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, marker), "1\n")
	e.H.Deps.State.EnterFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckCtrTasks, "test-hold")

	e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive cycles=%v want 1", got)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, marker)); err != nil {
		t.Fatalf("wedged marker dropped on inconclusive /proc scan: %v", err)
	}
	if !e.H.Deps.State.Exists(latchdefs.LatchPodTeardownWedged) {
		t.Fatal("LatchPodTeardownWedged released on inconclusive /proc scan")
	}
}
