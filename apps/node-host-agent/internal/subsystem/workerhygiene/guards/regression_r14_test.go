package guards_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

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

func TestR14NetfilterGuardDStateNftSafety(t *testing.T) {
	setupStat := func(t *testing.T, e *env, pid int, comm, state string, age time.Duration) string {
		t.Helper()
		const hz = 100
		startJiffies := int64(1000)
		uptimeSec := startJiffies/hz + int64(age.Seconds())
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "uptime"), fmt.Sprintf("%d.0 0\n", uptimeSec))
		pdir := filepath.Join(e.ProcDir, strconv.Itoa(pid))
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			fmt.Sprintf("%d (%s) %s 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n",
				pid, comm, state, startJiffies))
		if age > 0 {
			old := e.Now.Add(-age)
			if err := os.Chtimes(pdir, old, old); err != nil {
				t.Fatal(err)
			}
		}
		return pdir
	}

	t.Run("dstate_nft_fifo_cmdline_never_opened_and_logs_dstate", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 1
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
		pdir := setupStat(t, e, 6300, "nft", "D", 0)
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6300} },
			PidsOK:       func() bool { return true },
		}
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), ce)
		})

		if len(e.Kills) != 0 {
			t.Fatalf("D-state nft must not be SIGKILLed: %+v", e.Kills)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 0 {
			t.Fatalf("abort=%v want 0", got)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
		if logs := e.LogLines(t); !strings.Contains(logs, "uninterruptible D-state") {
			t.Fatalf("missing uninterruptible D-state log:\n%s", logs)
		}
	})

	t.Run("dstate_nft_cmdline_0000_logs_dstate_and_records_ok", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 1
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
		pdir := setupStat(t, e, 6301, "nft", "D", 0)
		cmdPath := filepath.Join(pdir, "cmdline")
		wdepstest.WriteFile(t, cmdPath, "nft\x00add\x00table\x00")
		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6301} },
			PidsOK:       func() bool { return true },
		})

		if len(e.Kills) != 0 {
			t.Fatalf("D-state nft must not be SIGKILLed: %+v", e.Kills)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 0 {
			t.Fatalf("abort=%v want 0", got)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
		if logs := e.LogLines(t); !strings.Contains(logs, "uninterruptible D-state") {
			t.Fatalf("missing uninterruptible D-state log:\n%s", logs)
		}
	})

	t.Run("sstate_nft_monitor_0000_aborts_and_readable_still_works", func(t *testing.T) {
		// Readable S-state nft monitor is excluded; readable S-state non-monitor nft is killed.
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 1
		e.H.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0

		pMon := setupStat(t, e, 6302, "nft", "S", 0)
		wdepstest.WriteFile(t, filepath.Join(pMon, "cmdline"), "nft\x00monitor\x00")
		old := e.Now.Add(-2 * time.Hour)
		if err := os.Chtimes(pMon, old, old); err != nil {
			t.Fatal(err)
		}
		pAdd := setupStat(t, e, 6303, "nft", "S", 0)
		wdepstest.WriteFile(t, filepath.Join(pAdd, "cmdline"), "nft\x00add\x00table\x00")
		if err := os.Chtimes(pAdd, old, old); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6302, 6303} },
			PidsOK:       func() bool { return true },
		})
		if len(e.Kills) != 1 || e.Kills[0].PID != 6303 {
			t.Fatalf("kills=%+v want only PID 6303 (nft monitor 6302 must be excluded)", e.Kills)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}

		if os.Geteuid() == 0 {
			return
		}
		// S-state nft with 0o000 cmdline must still abort cleanly without killing.
		cmdMon := filepath.Join(pMon, "cmdline")
		if err := os.Chmod(cmdMon, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdMon, 0o644) })
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6302} },
			PidsOK:       func() bool { return true },
		})
		if len(e.Kills) != 1 {
			t.Fatalf("S-state nft monitor with 0o000 cmdline must not be killed: %+v", e.Kills)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}
