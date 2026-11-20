package pods_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15KonnectivityStatsOnceOmissionAndEnvironFIFO(t *testing.T) {
	mkFIFOProc := func(t *testing.T, e *env, pid int, comm, state string) (string, []string) {
		t.Helper()
		pdir := filepath.Join(e.ProcDir, fmt.Sprint(pid))
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath,
			fmt.Sprintf("%d (%s) %s 1 1 1 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n", pid, comm, state))
		cmdFIFO := filepath.Join(pdir, "cmdline")
		envFIFO := filepath.Join(pdir, "environ")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(envFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		return statPath, []string{cmdFIFO, envFIFO}
	}

	t.Run("statsonce_omits_xstate_pid_fifo_cmdline_never_opened", func(t *testing.T) {
		e := fixture(t)
		_, fifos := mkFIFOProc(t, e, 6200, "proxy-agent", "X")
		chk := e.H.Check(wdeps.CheckKonn)
		runWithFIFOsGuard(t, fifos, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{6200} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return map[int]procfs.Stat{} },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
	})

	t.Run("statsonce_omits_dstate_proxy_agent_preserves_latch_and_fails", func(t *testing.T) {
		e := fixture(t)
		e.MkProc(t, 6201, "S", "/proxy-agent\x00--proxy-server-host=1.2.3.4\x00", "NODE_IP=10.9.9.9\x00")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "6201", "stat"),
			"6201 (proxy-agent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		e.H.Cycle(context.Background())
		if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("setup: LatchKonnectivityIPMismatch not armed")
		}
		chk := wdepstest.Check[*pods.KonnCheck](e.H, wdeps.CheckKonn)
		if chk.Fails != 1 {
			t.Fatalf("setup Fails=%d want 1", chk.Fails)
		}

		// PID 6201 replaced by D-state proxy-agent with FIFO cmdline/environ omitted from StatsOnce.
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "6201"))
		_, fifos := mkFIFOProc(t, e, 6201, "proxy-agent", "D")
		runWithFIFOsGuard(t, fifos, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{6201} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return map[int]procfs.Stat{} },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("LatchKonnectivityIPMismatch falsely exited when D-state proxy-agent omitted from StatsOnce")
		}
		if chk.Fails != 1 {
			t.Fatalf("Fails=%d want preserved 1", chk.Fails)
		}
	})

	t.Run("stale_statsonce_s_with_stat_0000_fifo_cmdline_and_environ_aborts", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		statPath, fifos := mkFIFOProc(t, e, 6202, "proxy-agent", "D")
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		staleSnap := map[int]procfs.Stat{
			6202: {Comm: "proxy-agent", HasComm: true, Fields: []string{"S", "1"}},
		}
		chk := e.H.Check(wdeps.CheckKonn)
		runWithFIFOsGuard(t, fifos, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{6202} },
				PidsOK:       func() bool { return true },
				StatsOnce:    func() map[int]procfs.Stat { return staleSnap },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}
