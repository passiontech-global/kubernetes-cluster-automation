// ctr_dz_shim_test.go — W12-KR2 coverage: an orphan containerd
// shim wedged in D (uninterruptible) or Z (zombie) state cannot
// be SIGKILLed away — ctr-tasks escalates it into the
// pod-teardown-wedged latch instead of burning a pointless kill.
package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// TestCtrTasksUnkillableShimEscalates: a D/Z-state orphan shim
// (in-scope socket, task dir gone, proc aged past the 5m window)
// must NOT consume a SIGKILL — the kernel can't deliver it — and
// must light state-pod-teardown-wedged for the NHC→SNR path.
func TestCtrTasksUnkillableShimEscalates(t *testing.T) {
	for _, state := range []string{"D", "Z"} {
		t.Run(state, func(t *testing.T) {
			e := fixture(t)
			sid := strings.Repeat("d", 64)
			e.MkStatProc(t, 9400, "containerd-shim-runc-v2", state, "")
			wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9400", "cmdline"),
				"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+
					sid+"\x00-address\x00/run/k0s/containerd.sock\x00")
			// Age the /proc entry past the 5m orphan window.
			old := e.Now.Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(e.ProcDir, "9400"), old, old); err != nil {
				t.Fatal(err)
			}
			env := &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     wdepstest.PidsOf(9400),
			}
			wdepstest.Check[*ctr.CtrTasksCheck](e.H,
				wdeps.CheckCtrTasks).Run(context.Background(), env)

			for _, k := range e.Kills {
				if k.PID == 9400 {
					t.Fatalf("%s-state orphan shim was signalled: %v", state, k)
				}
			}
			if !e.H.State.Exists("pod-teardown-wedged") {
				t.Fatalf("state-pod-teardown-wedged missing after %s-state shim", state)
			}
			if got := testutil.ToFloat64(e.H.Actions.WithLabelValues(
				wdeps.CheckCtrTasks, "shim_escalate")); got != 1 {
				t.Fatalf("shim_escalate actions=%v want 1", got)
			}
			if got := e.LogLines(t); !strings.Contains(got,
				"SIGKILL cannot clear") {
				t.Fatalf("missing escalation suspect line:\n%s", got)
			}
		})
	}
}

// TestCtrTasksRunnableShimStillKilled: a plain S-state orphan shim
// keeps the old SIGKILL verdict — the escalation only claims
// unkillable states.
func TestCtrTasksRunnableShimStillKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("e", 64)
	e.MkStatProc(t, 9401, "containerd-shim-runc-v2", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9401", "cmdline"),
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+
			sid+"\x00-address\x00/run/k0s/containerd.sock\x00")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9401"), old, old); err != nil {
		t.Fatal(err)
	}
	env := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     wdepstest.PidsOf(9401),
	}
	wdepstest.Check[*ctr.CtrTasksCheck](e.H,
		wdeps.CheckCtrTasks).Run(context.Background(), env)

	if len(e.Kills) != 1 || e.Kills[0].PID != 9401 ||
		e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("S-state orphan shim not SIGKILLed, kills=%v", e.Kills)
	}
	if e.H.State.Exists("pod-teardown-wedged") {
		t.Fatal("pod-teardown-wedged latched for a runnable shim")
	}
}
