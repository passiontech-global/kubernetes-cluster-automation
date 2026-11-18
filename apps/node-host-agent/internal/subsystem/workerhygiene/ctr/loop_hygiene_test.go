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

	// loop4: has a partition loop4p1 INSIDE its sysfs dir (Linux
	// layout) → must NOT detach (partition in use).
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop4", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop4", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop4", "loop", "backing_file"), "/var/lib/partitioned.raw (deleted)\n")
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop4", "loop4p1"), "")

	// loop5: autoclear=1 → must NOT detach (kernel-managed teardown).
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop5", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop5", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop5", "loop", "backing_file"), "/var/lib/autoclear.raw (deleted)\n")
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop5", "loop", "autoclear"), "1\n")

	// The detach gate requires the host /dev node to be visible in the
	// container — plant loop0's node under the fixture's HostDevDir.
	wdepstest.WriteFile(t,
		filepath.Join(e.H.Cfg.Wave3.HostDevDir, "loop0"), "")

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(_ context.Context, devPath string) error {
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
	// The detach runs in the host namespace via `losetup -d`, so the
	// path passed to the seam is the plain host /dev/loop0.
	want := filepath.Join("/dev", "loop0")
	if len(detached) != 1 || detached[0] != want {
		t.Fatalf("detached = %v, want [%s]", detached, want)
	}
	if e.H.Series.LoopDevicesReaped != 1 {
		t.Fatalf("LoopDevicesReaped = %d, want 1", e.H.Series.LoopDevicesReaped)
	}
}

// TestOrphanLoopMountedInOtherNamespaceKept: a loop that is mounted only in
// a container's mount namespace (not PID 1's) must never be detached.
func TestOrphanLoopMountedInOtherNamespaceKept(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	// PID 1's view does NOT mention loop0...
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile,
		"1 1 7:1 / / rw - ext4 /dev/vda1 rw\n")
	// ...but PID 2 (a container) mounts it in its own namespace.
	if err := os.MkdirAll(filepath.Join(e.ProcDir, "2"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2", "mountinfo"),
		"30 20 7:0 / /data rw - ext4 /dev/loop0 rw\n")

	sysBlock := e.H.Cfg.Wave3.SysBlockDir
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop0", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysBlock, "loop0", "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysBlock, "loop0", "loop", "backing_file"),
		"/var/lib/img.raw (deleted)\n")
	wdepstest.WriteFile(t,
		filepath.Join(e.H.Cfg.Wave3.HostDevDir, "loop0"), "")

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(_ context.Context, devPath string) error {
		detached = append(detached, devPath)
		return nil
	}

	chk := e.H.Check(wdeps.CheckMountinfo)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)
	e.Now = e.Now.Add(31 * time.Minute)
	chk.Run(context.Background(), ce)
	if len(detached) != 0 {
		t.Fatalf("detached a loop mounted in another namespace: %v", detached)
	}
}

// plantOrphanLoop creates a clean, stat-able orphan loop device dir
// under the fixture sysfs block tree.
func plantOrphanLoop(t *testing.T, e *env, dev string) {
	t.Helper()
	dir := filepath.Join(e.H.Cfg.Wave3.SysBlockDir, dev)
	if err := os.MkdirAll(filepath.Join(dir, "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "loop", "backing_file"),
		"/var/lib/"+dev+".raw (deleted)\n")
}

// TestOrphanLoopSiblingPartitionPathIgnored: a partition node placed
// BESIDE the loop device (/sys/block/loop6p1 — the old glob's path)
// is not a real Linux partition and must NOT protect the device.
func TestOrphanLoopSiblingPartitionPathIgnored(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile,
		"1 1 7:1 / / rw - ext4 /dev/vda1 rw\n")
	plantOrphanLoop(t, e, "loop6")
	wdepstest.WriteFile(t, filepath.Join(e.H.Cfg.Wave3.SysBlockDir, "loop6p1"), "")
	wdepstest.WriteFile(t, filepath.Join(e.H.Cfg.Wave3.HostDevDir, "loop6"), "")

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(_ context.Context, devPath string) error {
		detached = append(detached, devPath)
		return nil
	}
	chk := e.H.Check(wdeps.CheckMountinfo)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)
	e.Now = e.Now.Add(31 * time.Minute)
	chk.Run(context.Background(), ce)
	want := filepath.Join("/dev", "loop6")
	if len(detached) != 1 || detached[0] != want {
		t.Fatalf("detached=%v, want [%s] (sibling path must not shield the loop)", detached, want)
	}
}

// TestOrphanLoopDetachViaPID1Dev: the DaemonSet does not mount
// /host/dev, but losetup -d runs in PID 1's mount namespace — a
// /proc/1/root/dev/loopN node is enough to detach safely. A second
// orphan with neither path present must stay untouched.
func TestOrphanLoopDetachViaPID1Dev(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile,
		"1 1 7:1 / / rw - ext4 /dev/vda1 rw\n")
	plantOrphanLoop(t, e, "loop8") // reachable only via /proc/1/root/dev
	plantOrphanLoop(t, e, "loop9") // no device node anywhere → skip

	pid1Dev := filepath.Join(e.ProcDir, "1", "root", "dev")
	if err := os.MkdirAll(pid1Dev, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(pid1Dev, "loop8"), "")

	var detached []string
	e.H.Cfg.Seams.Host.DetachLoopFn = func(_ context.Context, devPath string) error {
		detached = append(detached, devPath)
		return nil
	}
	chk := e.H.Check(wdeps.CheckMountinfo)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)
	e.Now = e.Now.Add(31 * time.Minute)
	chk.Run(context.Background(), ce)
	want := filepath.Join("/dev", "loop8")
	if len(detached) != 1 || detached[0] != want {
		t.Fatalf("detached=%v, want [%s] via PID 1 /dev", detached, want)
	}
	if !strings.Contains(e.LogLines(t), "host /dev not mounted") {
		t.Fatalf("missing no-hostdev suspect line for loop9:\n%s", e.LogLines(t))
	}
}
