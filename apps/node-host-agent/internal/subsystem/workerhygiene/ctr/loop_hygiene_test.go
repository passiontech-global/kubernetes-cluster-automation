package ctr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestMountTableMaxRaiseAndSharedStormHysteresis(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	sysFS := filepath.Join(e.ProcDir, "sys", "fs")
	if err := os.MkdirAll(sysFS, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysFS, "mount-max"), "100\n")

	// 85 entries -> ratio 0.85 >= 0.80 -> auto-raise mount-max to 200 (ratio becomes 0.425).
	var sb strings.Builder
	for i := 0; i < 85; i++ {
		fmt.Fprintf(&sb, "%d 1 0:%d / /mnt/p%d rw shared:10 - tmpfs tmpfs rw\n", i+1, i+1, i)
	}
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, sb.String())

	chk := e.H.Check(wdeps.CheckMountinfo)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)

	gotMax, err := os.ReadFile(filepath.Join(sysFS, "mount-max"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(gotMax)) != "200" {
		t.Fatalf("mount-max=%q, want 200", string(gotMax))
	}
	if e.H.Series.MountMaxSharedPeers != 85 {
		t.Fatalf("MountMaxSharedPeers=%d, want 85", e.H.Series.MountMaxSharedPeers)
	}
	if e.H.State.Exists(latchdefs.LatchMountTablePressure) {
		t.Fatal("should not latch after raise dropped ratio to 0.425")
	}

	// Now trigger shared peer-group storm (MountSharedStormMax=10) for ConsecNeeded=2 cycles.
	e.H.Cfg.Wave3.MountSharedStormMax = 10
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchMountTablePressure) {
		t.Fatal("latched on 1st cycle, want ConsecNeeded=2")
	}
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchMountTablePressure) {
		t.Fatal("expected LatchMountTablePressure on 2nd cycle")
	}

	// Drop below clear threshold (< 2048 & <= 0.65): since MountSharedStormMax=10 was overridden,
	// clear threshold for shared is hardcoded < 2048 and ratio <= 0.65, so reducing to 5 mounts clears.
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 0:1 / / rw shared:10 - ext4 /dev/vda1 rw\n")
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchMountTablePressure) {
		t.Fatal("expected LatchMountTablePressure to clear below hysteresis threshold")
	}
}

func TestOrphanLoopDeviceReaper(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 7:1 / /mnt/live rw - ext4 /dev/loop1 rw\n")

	sysBlock := e.H.Cfg.Wave3.SysBlockDir
	// loop0: orphan (deleted), empty holders, not mounted -> should be reaped after 30m.
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop0", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop0", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop0", "loop", "backing_file"), "/var/lib/img.raw (deleted)\n")

	// loop1: deleted backing_file BUT still mounted in mountinfo -> must NOT reap.
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop1", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop1", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop1", "loop", "backing_file"), "/var/lib/mnt.raw (deleted)\n")

	// loop2: deleted backing_file BUT non-empty holders/ -> must NOT reap.
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop2", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop2", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop2", "loop", "backing_file"), "/var/lib/held.raw (deleted)\n")
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop2", "holders", "dm-0"), "")

	// loop3: deleted backing_file BUT holders is a regular file (ReadDir returns non-IsNotExist error) -> fail closed, must NOT reap.
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop3", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop3", "loop", "backing_file"), "/var/lib/unreadable.raw (deleted)\n")
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop3", "holders"), "not-a-dir")

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(devPath string) error {
		detached = append(detached, devPath)
		return nil
	}

	chk := e.H.Check(wdeps.CheckMountinfo)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}

	// Cycle 1: first sight -> marks loop-seen-loop0, does not detach yet.
	chk.Run(context.Background(), ce)
	if len(detached) != 0 {
		t.Fatalf("detached before 30m confirm: %v", detached)
	}

	// Advance clock 31m -> detaches only loop0.
	e.Now = e.Now.Add(31 * time.Minute)
	chk.Run(context.Background(), ce)
	want := filepath.Join(e.H.Cfg.Wave3.HostDevDir, "loop0")
	if len(detached) != 1 || detached[0] != want {
		t.Fatalf("detached = %v, want [%s]", detached, want)
	}
	if e.H.Series.LoopDevicesReaped != 1 {
		t.Fatalf("LoopDevicesReaped = %d, want 1", e.H.Series.LoopDevicesReaped)
	}
}
