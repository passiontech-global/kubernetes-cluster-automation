package guards_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15NetfilterGuardNftMonitorMidScanAndToggle(t *testing.T) {
	t.Run("nft_monitor_concurrent_sdzx_enoent_toggle_never_sigkills", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 1
		e.H.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0

		const hz = 100
		startJiffies := int64(1000)
		age := 2 * time.Hour
		uptimeSec := startJiffies/hz + int64(age.Seconds())
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "uptime"), fmt.Sprintf("%d.0 0\n", uptimeSec))

		pdir := filepath.Join(e.ProcDir, "6400")
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(pdir, "cmdline"), "nft\x00monitor\x00")
		old := e.Now.Add(-age)
		if err := os.Chtimes(pdir, old, old); err != nil {
			t.Fatal(err)
		}
		statPath := filepath.Join(pdir, "stat")
		tmpPath := filepath.Join(pdir, "stat.tmp")
		writeState := func(state string) {
			body := fmt.Sprintf("6400 (nft) %s 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n",
				state, startJiffies)
			_ = os.WriteFile(tmpPath, []byte(body), 0o644)
			_ = os.Rename(tmpPath, statPath)
		}
		writeState("S")

		var stop atomic.Bool
		toggleDone := make(chan struct{})
		go func() {
			defer close(toggleDone)
			states := []string{"S", "D", "Z", "X", "x", "ENOENT", "S"}
			i := 0
			for !stop.Load() {
				st := states[i%len(states)]
				if st == "ENOENT" {
					_ = os.Remove(statPath)
				} else {
					writeState(st)
				}
				i++
			}
		}()

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6400} },
			PidsOK:       func() bool { return true },
		}
		for range 150 {
			chk.Run(context.Background(), ce)
		}
		stop.Store(true)
		<-toggleDone

		if len(e.Kills) != 0 {
			t.Fatalf("falsely SIGKILLed nft monitor during S/D/Z/X/ENOENT toggle: %+v", e.Kills)
		}
	})

	t.Run("nft_stat_0000_aborts_without_killing", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 1
		e.H.Cfg.Wave2.NetfilterGuardHungCmdSec = 1
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0

		pdir := filepath.Join(e.ProcDir, "6401")
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath,
			"6401 (nft) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{6401} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected kills=%+v", e.Kills)
		}
	})
}
