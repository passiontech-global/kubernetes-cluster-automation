package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15CtrTasksStatErrorsAndCleanup(t *testing.T) {
	t.Run("stat_0000_with_fifo_cmdline_aborts_without_blocking", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		pdir := filepath.Join(e.ProcDir, "9300")
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath,
			"9300 (containerd-shim) D 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		chk := e.H.Check(wdeps.CheckCtrTasks)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9300} },
				PidsOK:       func() bool { return true },
				StatsOnce: func() map[int]procfs.Stat {
					return map[int]procfs.Stat{
						9300: {Comm: "containerd-shim", HasComm: true, Fields: []string{"D", "1"}},
					}
				},
			})
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9300} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 2 {
			t.Fatalf("abort=%v want 2", got)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "ok")); got != 0 {
			t.Fatalf("ok=%v want 0", got)
		}
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected kills=%+v", e.Kills)
		}
	})

	t.Run("stat_eisdir_and_enotdir_abort_without_opening_fifo", func(t *testing.T) {
		e := fixture(t)
		// PID 9301: /proc/9301/stat is a directory (EISDIR) + FIFO cmdline.
		pdir := filepath.Join(e.ProcDir, "9301")
		if err := os.MkdirAll(filepath.Join(pdir, "stat"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		// PID 9302: /proc/9302 is a regular file (ENOTDIR).
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9302"), "not-a-dir")

		chk := e.H.Check(wdeps.CheckCtrTasks)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9301} },
				PidsOK:       func() bool { return true },
			})
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9302} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 2 {
			t.Fatalf("abort=%v want 2", got)
		}
	})

	t.Run("stat_enoent_with_fifo_cmdline_skips_cleanly", func(t *testing.T) {
		e := fixture(t)
		pdir := filepath.Join(e.ProcDir, "9303")
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckCtrTasks)
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9303} },
				PidsOK:       func() bool { return true },
			})
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "ok")); got != 1 {
			t.Fatalf("ok=%v want 1", got)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 0 {
			t.Fatalf("abort=%v want 0", got)
		}
	})

	t.Run("wedged_task_cleanup_with_unrelated_pid_stat_0000_fifo_cmdline", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		taskID := strings.Repeat("a", 64)
		taskDir := filepath.Join(e.CtrDir, taskID)
		if err := os.MkdirAll(taskDir, 0o755); err != nil {
			t.Fatal(err)
		}

		pdir := filepath.Join(e.ProcDir, "9304")
		statPath := filepath.Join(pdir, "stat")
		wdepstest.WriteFile(t, statPath,
			"9304 (unrelated) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

		chk := e.H.Check(wdeps.CheckCtrTasks)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return []int{9304} },
			PidsOK:       func() bool { return true },
		}
		runWithFIFOGuard(t, cmdFIFO, func() {
			chk.Run(context.Background(), ce) // stamps wedged-seen-<id>
			e.Now = e.Now.Add(10 * time.Minute)
			chk.Run(context.Background(), ce) // >=5m confirmed -> cleans taskDir without blocking
		})
		if _, err := os.Stat(taskDir); !os.IsNotExist(err) {
			t.Fatalf("wedged task dir was not cleaned: err=%v", err)
		}
	})
}

func TestR15CtrMetaDStateOrphanShimOmittedFromStatsOnce(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "all healthy", nil
	}
	sid := strings.Repeat("b", 64)
	metaTaskDir := filepath.Join(filepath.Dir(e.CtrDir), "k8s.io", sid)
	if err := os.MkdirAll(metaTaskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(metaTaskDir, "init.pid"), "999999\n")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(metaTaskDir, old, old); err != nil {
		t.Fatal(err)
	}

	pdir := filepath.Join(e.ProcDir, "9350")
	e.MkStatProc(t, 9350, "containerd-shim", "D", "")
	fdDir := filepath.Join(pdir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.CtrDir, sid, "log.json"), filepath.Join(fdDir, "9")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(pdir, old, old); err != nil {
		t.Fatal(err)
	}

	chk := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	// e.StatsOnce omits PID 9350 -> countMetaOrphanShims MUST still invoke dzShimScopeChecked!
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{9350} },
		PidsOK:       func() bool { return true },
		StatsOnce:    func() map[int]procfs.Stat { return map[int]procfs.Stat{} },
	}
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatalf("LatchContainerdCorrupt not armed when D-state orphan shim omitted from StatsOnce:\n%s",
			e.LogLines(t))
	}

	// Subcase: fd 0o000 with StatsOnce omitting pid -> aborts and preserves LatchContainerdCorrupt.
	if os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(fdDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt cleared when fd 0o000 on omitted D-state shim")
	}
}
