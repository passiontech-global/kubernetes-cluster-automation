package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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

func TestR14KernelNetShimAndVMADZXStateSafety(t *testing.T) {
	t.Run("kernel_net_shim_dzx_with_fifo_cmdline_never_opens_cmdline", func(t *testing.T) {
		e := fixture(t)
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "1", "net", "netstat"),
			"TcpExt: ListenDrops ListenOverflows\nTcpExt: 0 0\n")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "net", "softnet_stat"),
			"00000001 00000000 00000000\n")

		for _, tc := range []struct {
			pid   int
			state string
		}{
			{7100, "D"},
			{7101, "Z"},
			{7102, "X"},
		} {
			pdir := filepath.Join(e.ProcDir, fmt.Sprint(tc.pid))
			wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
				fmt.Sprintf("%d (containerd-shim) %s 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
					tc.pid, tc.state))
			wdepstest.WriteFile(t, filepath.Join(pdir, "comm"), "containerd-shim\n")
			wdepstest.WriteFile(t, filepath.Join(pdir, "status"), "VmRSS:\t1024 kB\n")
			cmdFIFO := filepath.Join(pdir, "cmdline")
			if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if f, err := os.OpenFile(cmdFIFO, os.O_RDWR, 0); err == nil {
					_ = f.Close()
				}
			})
		}

		chk := e.H.Check(wdeps.CheckKernelNetShim)
		// Test both StatsOnce==nil and StatsOnce missing the pids (!known path).
		done := make(chan struct{})
		go func() {
			defer close(done)
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{7100, 7101, 7102} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return map[int]procfs.Stat{} },
			})
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{7100, 7101, 7102} },
				PidsOK:       func() bool { return true },
			})
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("KernelNetShimCheck blocked opening FIFO cmdline on D/Z/X shim")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "ok")); got != 2 {
			t.Fatalf("ok=%v want 2", got)
		}
	})

	t.Run("vma_pressure_xstate_fifo_maps_never_opened", func(t *testing.T) {
		e := fixture(t)
		if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "max_map_count"), "100\n")

		pdir := filepath.Join(e.ProcDir, "7105")
		fields := make([]string, 21)
		fields[0] = "X"
		for i := 1; i < 20; i++ {
			fields[i] = "0"
		}
		fields[20] = "2147483648"
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			fmt.Sprintf("7105 (java) %s\n", strings.Join(fields, " ")))
		mapsFIFO := filepath.Join(pdir, "maps")
		if err := unix.Mkfifo(mapsFIFO, 0o644); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckCgroupThrottle)
		runWithFIFOGuard(t, mapsFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				PidsOnce:     func() []int { return []int{7105} },
				PidsOK:       func() bool { return true },
			})
		})
	})
}
