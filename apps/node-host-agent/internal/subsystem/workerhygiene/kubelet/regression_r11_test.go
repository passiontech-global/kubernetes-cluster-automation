package kubelet_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

func TestR11KubeletStallSandboxCtlRoot0000DoesNotFalsePhantomRestart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	for i := 0; i < kubelet.PoddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.KubepodsDir, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sbRoot := e.H.Cfg.SandboxCtlRoot
	if err := os.MkdirAll(sbRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sbRoot, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sbRoot, 0o755) })

	// Pre-arm stall latch to verify abort does not clear it either.
	e.H.State.Enter(latchdefs.LatchKubeletRuntimeStall, "prior")

	e.H.Check(wdeps.CheckStall).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
	})
	e.H.Check(wdeps.CheckStall).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
	})
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("falsely restarted k0sworker on unreadable SandboxCtlRoot")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckStall, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2", got)
	}
	if !e.H.State.Exists(latchdefs.LatchKubeletRuntimeStall) {
		t.Fatal("LatchKubeletRuntimeStall cleared on unreadable SandboxCtlRoot")
	}

	// Restoring SandboxCtlRoot with a live sandbox dir clears cleanly.
	if err := os.Chmod(sbRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sbRoot, "sb1"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Check(wdeps.CheckStall).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
	})
	if e.H.State.Exists(latchdefs.LatchKubeletRuntimeStall) {
		t.Fatal("LatchKubeletRuntimeStall did not exit after SandboxCtlRoot recovery")
	}
}
