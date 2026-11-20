package ctr_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestMountinfoPodVolSeenPreservedOnPodsDirErrors(t *testing.T) {
	t.Run("EACCES_0000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		uid := strings.Repeat("a", 36)
		podDir := filepath.Join(e.KubepodsDir, uid)
		volMount := filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", "cache")
		wdepstest.WriteFile(t, filepath.Join(volMount, "junk"), "x")
		stale := e.Now.Add(-time.Hour)
		if err := os.Chtimes(podDir, stale, stale); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(e.StateDir, "mi-vol-seen-"+uid)
		wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-31*time.Minute).Unix()))
		writeMountinfo(t, e, []string{miLine(volMount)})

		if err := os.Chmod(e.KubepodsDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.KubepodsDir, 0o755) })

		miCycle(e)
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("mi-vol-seen marker pruned under PodsDir 0o000: %v", err)
		}
	})

	t.Run("ENOTDIR", func(t *testing.T) {
		e := fixture(t)
		uid := strings.Repeat("b", 36)
		marker := filepath.Join(e.StateDir, "mi-vol-seen-"+uid)
		wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-31*time.Minute).Unix()))
		volMount := filepath.Join(e.KubepodsDir, uid, "volumes", "kubernetes.io~empty-dir", "cache")
		writeMountinfo(t, e, []string{miLine(volMount)})

		if err := os.RemoveAll(e.KubepodsDir); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, e.KubepodsDir, "not a directory\n")

		miCycle(e)
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("mi-vol-seen marker pruned under PodsDir ENOTDIR: %v", err)
		}
	})
}

func TestMountPressureInconclusiveMountMaxPreservesLatch(t *testing.T) {
	setupArmed := func(t *testing.T) (*env, string) {
		t.Helper()
		e := fixture(t)
		e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
		e.H.Cfg.Wave3.MountMaxCeiling = 100 // prevent auto-raise
		sysFS := filepath.Join(e.ProcDir, "sys", "fs")
		if err := os.MkdirAll(sysFS, 0o755); err != nil {
			t.Fatal(err)
		}
		mountMaxPath := filepath.Join(sysFS, "mount-max")
		wdepstest.WriteFile(t, mountMaxPath, "100\n")
		var sb strings.Builder
		for i := range 85 {
			fmt.Fprintf(&sb, "%d 1 0:%d / /mnt/p%d rw - tmpfs tmpfs rw\n", i+1, i+1, i)
		}
		wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, sb.String())
		chk := e.H.Check(wdeps.CheckMountinfo)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchMountTablePressure) {
			t.Fatal("setup: LatchMountTablePressure not armed")
		}
		return e, mountMaxPath
	}

	t.Run("EACCES_0000_and_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, mountMaxPath := setupArmed(t)
		if err := os.Chmod(mountMaxPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(mountMaxPath, 0o644) })

		e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckMountinfo, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchMountTablePressure) {
			t.Fatal("LatchMountTablePressure falsely exited on mount-max EACCES")
		}
		if e.H.Series.MountTableUtilRatio != 0.85 {
			t.Fatalf("MountTableUtilRatio=%v want preserved 0.85", e.H.Series.MountTableUtilRatio)
		}

		// Recovery: restore permissions and drop mount count below clearRatio.
		if err := os.Chmod(mountMaxPath, 0o644); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 0:1 / / rw - ext4 /dev/vda1 rw\n")
		e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if e.H.State.Exists(latchdefs.LatchMountTablePressure) {
			t.Fatal("LatchMountTablePressure did not exit after recovery")
		}
	})

	t.Run("ENOTDIR_and_unparseable", func(t *testing.T) {
		e, mountMaxPath := setupArmed(t)
		wdepstest.WriteFile(t, mountMaxPath, "corrupt\n")
		e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if !e.H.State.Exists(latchdefs.LatchMountTablePressure) {
			t.Fatal("LatchMountTablePressure falsely exited on unparseable mount-max")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckMountinfo, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}

		// ENOTDIR: replace sys/fs with a regular file.
		sysFS := filepath.Dir(mountMaxPath)
		if err := os.RemoveAll(sysFS); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, sysFS, "not a dir\n")
		e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if !e.H.State.Exists(latchdefs.LatchMountTablePressure) {
			t.Fatal("LatchMountTablePressure falsely exited on mount-max ENOTDIR")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckMountinfo, "abort")); got != 2 {
			t.Fatalf("abort=%v want 2", got)
		}
	})

	t.Run("ENOENT_fallback_still_clears", func(t *testing.T) {
		e, mountMaxPath := setupArmed(t)
		if err := os.Remove(mountMaxPath); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 0:1 / / rw - ext4 /dev/vda1 rw\n")
		e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if e.H.State.Exists(latchdefs.LatchMountTablePressure) {
			t.Fatal("expected LatchMountTablePressure to clear on ENOENT fallback with 1 mount")
		}
	})
}

func TestCtrMetaJournalErrorPreservesFailsAndLatch(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "Nov 10 01:00:00 node containerd: failed to loadmeta: invalid freelist page", nil
	}
	chk := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	cycle := &wdeps.CycleEnv{
		PidsOnce:     func() []int { return nil },
		PidsOK:       func() bool { return true },
		WorkerActive: true,
	}
	chk.Run(context.Background(), cycle)
	chk.Run(context.Background(), cycle)
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("setup: LatchContainerdCorrupt not armed")
	}

	// Journal probe errors out while PidsOK=true and 0 orphan shims -> must abort and preserve latch.
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "", errors.New("journalctl exited 1: EACCES")
	}
	chk.Run(context.Background(), cycle)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt falsely exited on journal probe error")
	}

	// Clean journal recovers cleanly.
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "all healthy", nil
	}
	chk.Run(context.Background(), cycle)
	if e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt did not exit on clean journal")
	}
}

func TestLoopHygieneAutoclearUnreadableDoesNotDetach(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 7:1 / /mnt/live rw - ext4 /dev/loop1 rw\n")

	sysBlock := e.H.Cfg.Wave3.SysBlockDir
	loopDir := filepath.Join(sysBlock, "loop0", "loop")
	if err := os.MkdirAll(loopDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop0", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(loopDir, "backing_file"), "/var/lib/img.raw (deleted)\n")
	autoclearPath := filepath.Join(loopDir, "autoclear")
	wdepstest.WriteFile(t, autoclearPath, "1\n")

	marker := filepath.Join(e.StateDir, "loop-seen-loop0")
	wdepstest.WriteFile(t, marker, fmt.Sprintf("%d\n", e.Now.Add(-31*time.Minute).Unix()))
	hostDev := filepath.Join(e.H.Cfg.Wave3.HostDevDir, "loop0")
	wdepstest.WriteFile(t, hostDev, "dev")

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(_ context.Context, dev string) error {
		detached = append(detached, dev)
		return nil
	}

	if err := os.Chmod(autoclearPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(autoclearPath, 0o644) })

	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if len(detached) != 0 {
		t.Fatalf("detached loop device when autoclear returned EACCES: %v", detached)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("loop-seen-loop0 marker pruned while autoclear unreadable: %v", err)
	}

	// Restore autoclear=0 -> confirmed orphan detaches cleanly.
	if err := os.Chmod(autoclearPath, 0o644); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, autoclearPath, "0\n")
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if len(detached) != 1 || detached[0] != "/dev/loop0" {
		t.Fatalf("detached=%v want [/dev/loop0]", detached)
	}
}
