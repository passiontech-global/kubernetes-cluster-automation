package pods_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func runWithFIFOsGuard(t *testing.T, fifoPaths []string, fn func()) {
	t.Helper()
	t.Cleanup(func() {
		for _, p := range fifoPaths {
			if f, err := os.OpenFile(p, os.O_RDWR, 0); err == nil {
				_ = f.Close()
			}
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("blocked opening FIFO in %v (violates D/Z/X mmBlocked safety)", fifoPaths)
	}
}

func TestR14KonnectivityDZXStateSkipsCmdlineAndEnviron(t *testing.T) {
	mkFIFOProc := func(t *testing.T, e *env, pid int, state string) []string {
		t.Helper()
		pdir := filepath.Join(e.ProcDir, fmt.Sprint(pid))
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			fmt.Sprintf("%d (proxy-agent) %s 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n", pid, state))
		cmdFIFO := filepath.Join(pdir, "cmdline")
		envFIFO := filepath.Join(pdir, "environ")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(envFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		return []string{cmdFIFO, envFIFO}
	}

	t.Run("dstate_proxy_agent_fifo_aborts_without_blocking", func(t *testing.T) {
		e := fixture(t)
		fifos := mkFIFOProc(t, e, 6100, "D")
		chk := e.H.Check(wdeps.CheckKonn)
		runWithFIFOsGuard(t, fifos, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{6100} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1 for D-state proxy-agent candidate", got)
		}
	})

	t.Run("zx_state_proxy_agent_fifo_skips_without_blocking", func(t *testing.T) {
		e := fixture(t)
		var fifos []string
		fifos = append(fifos, mkFIFOProc(t, e, 6101, "Z")...)
		fifos = append(fifos, mkFIFOProc(t, e, 6102, "X")...)
		chk := e.H.Check(wdeps.CheckKonn)
		runWithFIFOsGuard(t, fifos, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{6101, 6102} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
	})
}
