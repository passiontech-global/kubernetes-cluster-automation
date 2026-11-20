package guards_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR12NetfilterGuardCmdlineAndStatEACCES(t *testing.T) {
	setupNetfilterProc := func(t *testing.T, e *env, pid int, comm, state string, argv []string, age time.Duration) {
		t.Helper()
		const hz = 100
		startJiffies := int64(1000)
		uptimeSec := startJiffies/hz + int64(age.Seconds())
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "uptime"), fmt.Sprintf("%d.0 0\n", uptimeSec))
		pdir := filepath.Join(e.ProcDir, strconv.Itoa(pid))
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			fmt.Sprintf("%d (%s) %s 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n",
				pid, comm, state, startJiffies))
		if len(argv) > 0 {
			var cmd string
			for _, a := range argv {
				cmd += a + "\x00"
			}
			wdepstest.WriteFile(t, filepath.Join(pdir, "cmdline"), cmd)
		}
		old := e.Now.Add(-age)
		if err := os.Chtimes(pdir, old, old); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("nft_monitor_cmdline_0000_no_kill_and_aborts", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 2
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
		setupNetfilterProc(t, e, 6201, "nft", "S", []string{"nft", "monitor"}, 2*time.Hour)

		cmdPath := filepath.Join(e.ProcDir, "6201", "cmdline")
		if err := os.Chmod(cmdPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6201} },
			PidsOK:       func() bool { return true },
		}
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		if len(e.Kills) != 0 {
			t.Fatalf("falsely SIGKILLed nft monitor on cmdline EACCES: %+v", e.Kills)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 2 {
			t.Fatalf("abort=%v want 2", got)
		}

		if err := os.Chmod(cmdPath, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce)
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected kill after cmdline restored: %+v", e.Kills)
		}
	})

	t.Run("stat_0000_preserves_streak_and_recovers", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
		e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 2
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
		setupNetfilterProc(t, e, 6210, "iptables", "S", []string{"iptables", "-L"}, 2*time.Hour)

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{6210} },
			PidsOK:       func() bool { return true },
		}
		chk.Run(context.Background(), ce) // streak = 1
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected kill on cycle 1: %+v", e.Kills)
		}

		statPath := filepath.Join(e.ProcDir, "6210", "stat")
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		chk.Run(context.Background(), ce) // abort, preserves streak=1
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		if err := os.Chmod(statPath, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce) // streak = 2 -> SIGKILL
		if len(e.Kills) != 1 || e.Kills[0].PID != 6210 {
			t.Fatalf("kills=%+v want PID 6210 killed from preserved streak", e.Kills)
		}

		// Exited PID (ENOENT) drops streak cleanly without aborting.
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "6210"))
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1 (ENOENT should not abort)", got)
		}
	})
}

func TestR12CNINetnsProcNsNetEACCESAbortsWithoutReap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	netnsDir := filepath.Join(t.TempDir(), "netns")
	if err := os.MkdirAll(netnsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Net.NetnsDir = netnsDir
	netnsFile := filepath.Join(netnsDir, "cni-live-pod")
	wdepstest.WriteFile(t, netnsFile, "nsfs")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(netnsFile, old, old); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(e.StateDir, "cni-netns-seen-cni-live-pod")
	wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-45*time.Minute).Unix()))

	// PID 1 has readable ns/net (different inode); PID 500 owns the netns via hardlink (same inode)
	// while /proc/500/ns is 0o000.
	ns1 := filepath.Join(e.ProcDir, "1", "ns")
	if err := os.MkdirAll(ns1, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(ns1, "net"), "host-ns")

	ns500 := filepath.Join(e.ProcDir, "500", "ns")
	if err := os.MkdirAll(ns500, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(netnsFile, filepath.Join(ns500, "net")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ns500, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ns500, 0o755) })

	e.SDReply["umount"] = ""
	chk := e.H.Check(wdeps.CheckCNINetns)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{1, 500} },
		PidsOK:       func() bool { return true },
	}
	chk.Run(context.Background(), ce)

	if e.SDRan("umount") {
		t.Fatalf("falsely umounted live netns when /proc/500/ns returned EACCES: cmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(netnsFile); err != nil {
		t.Fatalf("live netns file removed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker wiped on abort: %v", err)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCNINetns, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}

	// Restore /proc/500/ns -> sees inode is live, drops marker without umount.
	if err := os.Chmod(ns500, 0o755); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), ce)
	if e.SDRan("umount") {
		t.Fatalf("umounted live netns after recovery: cmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected stale marker cleared once live process seen: err=%v", err)
	}
}
