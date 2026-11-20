package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func runWithFIFOGuard(t *testing.T, fifoPath string, fn func()) {
	t.Helper()
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifoPath, os.O_RDWR, 0); err == nil {
			_ = f.Close()
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
		t.Fatalf("blocked opening FIFO %s (violates D/Z/X mmBlocked safety)", fifoPath)
	}
}

func TestR14CtrDZXStateFIFOCmdlineNeverOpened(t *testing.T) {
	t.Run("ctr_meta_xstate_shim_fifo_cmdline", func(t *testing.T) {
		e := fixture(t)
		pdir := filepath.Join(e.ProcDir, "9200")
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			"9200 (containerd-shim) X 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}

		chk := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9200} },
				PidsOK:       func() bool { return true },
				JournalOnce:  func() string { return "" },
				JournalOK:    func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
	})

	t.Run("ctr_tasks_xstate_shim_fifo_cmdline", func(t *testing.T) {
		e := fixture(t)
		pdir := filepath.Join(e.ProcDir, "9201")
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			"9201 (containerd-shim) X 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckCtrTasks)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9201} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
	})

	t.Run("hung_runc_dstate_fifo_cmdline", func(t *testing.T) {
		e := hungEnv(t, 1)
		pdir := filepath.Join(e.ProcDir, "9202")
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			"9202 (runc) D 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		wdepstest.WriteFile(t, filepath.Join(pdir, "wchan"), "blk_mq_get_tag\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		ageProc(t, e, 9202, 10*time.Minute)

		chk := hungCheck(e)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9202} },
				PidsOK:       func() bool { return true },
			})
		})
		if len(e.Kills) != 0 {
			t.Fatalf("D-state runc must not be SIGKILLed: %+v", e.Kills)
		}
	})
}
