// fd_swap_guards_test.go — coverage for the unlinked-open-files
// guard (deleted-but-open fd sweep + shipper SIGHUP) and the
// cgroup-swap-leak guard (kubepods memory.swap.max cap).
package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// mkDeletedFD links <proc>/<pid>/fd/<fd> to a " (deleted)" target —
// readlink works on the dangling symlink exactly like the real
// magic link; the DeletedFDStatFn seam supplies dev/ino/size.
func (e *env) mkDeletedFD(t *testing.T, pid, fd int, target string) {
	t.Helper()
	dir := filepath.Join(e.ProcDir, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target+" (deleted)",
		filepath.Join(dir, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
}

// deletedStat is the canned DeletedFDStatFn answer — one entry per
// fd link path keyed "<pid>:<fd>".
type deletedStat struct {
	dev  uint64
	ino  uint64
	size int64
}

func (e *env) stubDeletedFDStats(stats map[string]deletedStat) {
	e.H.Cfg.Seams.Host.DeletedFDStatFn = func(path string) (uint64, uint64, int64, bool) {
		key := strings.TrimPrefix(path, e.ProcDir+"/")
		parts := strings.Split(key, "/")
		if len(parts) != 3 {
			return 0, 0, 0, false
		}
		s, ok := stats[parts[0]+":"+parts[2]]
		if !ok {
			return 0, 0, 0, false
		}
		return s.dev, s.ino, s.size, true
	}
}

func mib(n int64) int64 { return n << 20 }

// --- unlinked-open-files ---

func TestUnlinkedOpenFilesSweepAndSighup(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	e.DiskUsed = 0.90 // above the 80% watermark

	// fluent-bit holds a 300MiB deleted log, vector a 300MiB one
	// (shipper-held total 600MiB >= 512MiB → SIGHUP both), an
	// unrelated proc holds a third file — counted, not signalled.
	for _, pid := range []int{4242, 4243, 4244} {
		e.MkStatProc(t, pid, "app", "S", "")
	}
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4242", "comm"), "fluent-bit\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4243", "comm"), "vector\n")
	e.mkDeletedFD(t, 4242, 3, "/var/log/app.log")
	e.mkDeletedFD(t, 4243, 5, "/var/log/big.log")
	e.mkDeletedFD(t, 4244, 7, "/tmp/scratch.bin")
	// vector also holds the same inode as app — global dedup keeps
	// the total at 3 files but the shipper still gets the bytes.
	e.mkDeletedFD(t, 4243, 9, "/tmp/scratch.bin")
	e.stubDeletedFDStats(map[string]deletedStat{
		"4242:3": {dev: 100, ino: 11, size: mib(300)},
		"4243:5": {dev: 100, ino: 22, size: mib(300)},
		"4244:7": {dev: 100, ino: 33, size: mib(300)},
		"4243:9": {dev: 100, ino: 33, size: mib(300)}, // shared inode
	})
	env := &wdeps.CycleEnv{WorkerActive: true}

	wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](h, wdeps.CheckUnlinkedOpenFiles).Run(ctx, env)

	if h.UnlinkedOpenFileCount != 3 {
		t.Fatalf("count=%d want 3 (shared inode deduped)",
			h.UnlinkedOpenFileCount)
	}
	if h.UnlinkedOpenFileBytes != mib(900) {
		t.Fatalf("bytes=%d want %d", h.UnlinkedOpenFileBytes, mib(900))
	}
	var sigs []wdepstest.KillRecord
	for _, k := range e.Kills {
		if k.Sig == syscall.SIGHUP {
			sigs = append(sigs, k)
		}
	}
	if len(sigs) != 2 {
		t.Fatalf("SIGHUPs=%v want 2 (fluent-bit + vector)", e.Kills)
	}
	got := map[int]bool{sigs[0].PID: true, sigs[1].PID: true}
	if !got[4242] || !got[4243] || got[4244] {
		t.Fatalf("SIGHUP pids=%v want {4242,4243}", got)
	}
	// The 15m scan stamp + the 30m budget both suppress a repeat:
	// advancing past the scan interval must still not re-signal.
	e.Now = e.Now.Add(16 * time.Minute)
	wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](h, wdeps.CheckUnlinkedOpenFiles).Run(ctx, env)
	n := 0
	for _, k := range e.Kills {
		if k.Sig == syscall.SIGHUP {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("SIGHUP repeated inside the 30m budget: kills=%v", e.Kills)
	}
	// Shipper-held total below the 512MiB floor → no signal (past
	// the 30m budget too — this is the floor, not the cooldown).
	e.Kills = nil
	e.Now = e.Now.Add(31 * time.Minute)
	for _, fd := range []string{"5", "9"} {
		if err := os.Remove(filepath.Join(e.ProcDir, "4243", "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](h, wdeps.CheckUnlinkedOpenFiles).Run(ctx, env)
	for _, k := range e.Kills {
		if k.Sig == syscall.SIGHUP {
			t.Fatal("SIGHUP fired below the shipper-held floor")
		}
	}
}

func TestUnlinkedOpenFilesHoldLocalActionPreservesBudget(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.90
	e.MkStatProc(t, 4343, "app", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4343", "comm"), "fluent-bit\n")
	e.mkDeletedFD(t, 4343, 3, "/var/log/app.log")
	e.stubDeletedFDStats(map[string]deletedStat{"4343:3": {dev: 1, ino: 1, size: mib(600)}})
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			return map[string]string{nodecond.KuredLockAnno: `{"nodeID":"node-a"}`}, nil
		},
	}

	wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](e.H, wdeps.CheckUnlinkedOpenFiles).Run(
		context.Background(), &wdeps.CycleEnv{WorkerActive: true})

	if len(e.Kills) != 0 {
		t.Fatalf("SIGHUP fired while held: %v", e.Kills)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-unlinked-fd-sighup")); !os.IsNotExist(err) {
		t.Fatal("last-unlinked-fd-sighup budget spent while held")
	}
}

func TestUnlinkedOpenFilesBelowWatermarkSkips(t *testing.T) {
	e := fixture(t)
	h := e.H
	e.DiskUsed = 0.50              // below the 80% watermark
	h.UnlinkedOpenFileBytes = 1234 // stale values must zero out
	h.UnlinkedOpenFileCount = 7
	e.mkDeletedFD(t, 4242, 3, "/var/log/app.log")
	wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](h, wdeps.CheckUnlinkedOpenFiles).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if h.UnlinkedOpenFileBytes != 0 || h.UnlinkedOpenFileCount != 0 {
		t.Fatalf("stale series kept below watermark: bytes=%d count=%d",
			h.UnlinkedOpenFileBytes, h.UnlinkedOpenFileCount)
	}
}

func TestUnlinkedOpenFilesSizeFloor(t *testing.T) {
	e := fixture(t)
	h := e.H
	e.DiskUsed = 0.90
	e.MkStatProc(t, 4242, "app", "S", "")
	e.mkDeletedFD(t, 4242, 3, "/var/log/tiny.log")
	e.stubDeletedFDStats(map[string]deletedStat{
		"4242:3": {dev: 100, ino: 11, size: mib(32)}, // below the 64MiB floor
	})
	wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](h, wdeps.CheckUnlinkedOpenFiles).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if h.UnlinkedOpenFileCount != 0 || h.UnlinkedOpenFileBytes != 0 {
		t.Fatalf("sub-floor file counted: bytes=%d count=%d",
			h.UnlinkedOpenFileBytes, h.UnlinkedOpenFileCount)
	}
}

// --- cgroup-swap-leak ---

func TestCgroupSwapLeakCapsSlices(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	kp := filepath.Join(cg, "kubepods.slice")
	wdepstest.WriteFile(t, filepath.Join(kp, "memory.swap.current"), "134217728\n") // 128MiB
	wdepstest.WriteFile(t, filepath.Join(kp, "memory.swap.max"), "max\n")
	for _, q := range []string{"kubepods-burstable.slice", "kubepods-besteffort.slice"} {
		wdepstest.WriteFile(t, filepath.Join(kp, q, "memory.swap.max"), "max\n")
	}
	env := &wdeps.CycleEnv{WorkerActive: true}

	wdepstest.Check[*runtime.CgroupSwapCheck](h, wdeps.CheckCgroupSwap).Run(ctx, env)

	if h.KubepodsSwapUsedBytes != 128<<20 {
		t.Fatalf("swapUsed=%d want 128MiB", h.KubepodsSwapUsedBytes)
	}
	for _, p := range []string{
		filepath.Join(kp, "memory.swap.max"),
		filepath.Join(kp, "kubepods-burstable.slice", "memory.swap.max"),
		filepath.Join(kp, "kubepods-besteffort.slice", "memory.swap.max"),
	} {
		if got := nhReadFile(t, p); got != "0\n" {
			t.Fatalf("%s=%q want \"0\\n\"", p, got)
		}
	}
	// Idempotent: the cap already stands — a second high cycle must
	// not rewrite or re-log the ACTION.
	wdepstest.Check[*runtime.CgroupSwapCheck](h, wdeps.CheckCgroupSwap).Run(ctx, env)
	if n := strings.Count(e.LogLines(t),
		"ACTION: cgroup-swap-leak capped pod swap"); n != 1 {
		t.Fatalf("cap ACTION logged %d times want 1", n)
	}
}

func TestCgroupSwapLeakBelowFloorAndDormant(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	kp := filepath.Join(cg, "kubepods.slice")
	wdepstest.WriteFile(t, filepath.Join(kp, "memory.swap.current"), "1024\n") // 1KiB
	wdepstest.WriteFile(t, filepath.Join(kp, "memory.swap.max"), "max\n")
	env := &wdeps.CycleEnv{WorkerActive: true}

	wdepstest.Check[*runtime.CgroupSwapCheck](h, wdeps.CheckCgroupSwap).Run(ctx, env)
	if got := nhReadFile(t, filepath.Join(kp, "memory.swap.max")); got != "max\n" {
		t.Fatalf("swap.max rewritten below the floor: %q", got)
	}
	if h.KubepodsSwapUsedBytes != 1024 {
		t.Fatalf("swapUsed=%d want 1024 (gauge still reports)", h.KubepodsSwapUsedBytes)
	}

	// No memory.swap.current at all → cgroup v1/unmounted → abort.
	h2 := fixture(t)
	h2.H.Cfg.Runtime.CgroupRoot = t.TempDir()
	wdepstest.Check[*runtime.CgroupSwapCheck](h2.H, wdeps.CheckCgroupSwap).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if h2.H.KubepodsSwapUsedBytes != 0 {
		t.Fatal("gauge written on a dormant (no swap.current) cycle")
	}
}

func TestUnlinkedOpenFilesPidsOKFalseAndProcErrorPreserveGaugesAndLastScan(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	e.DiskUsed = 0.90
	h.UnlinkedOpenFileBytes = mib(256)
	h.UnlinkedOpenFileCount = 2

	chk := wdepstest.Check[*runtime.UnlinkedOpenFilesCheck](h, wdeps.CheckUnlinkedOpenFiles)

	// PidsOnce() == nil + PidsOK() == false must abort "inconclusive" without zeroing gauges or stamping lastScan.
	chk.Run(ctx, &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return nil },
		PidsOK:       func() bool { return false },
	})
	if got := testutil.ToFloat64(h.Cycles.WithLabelValues(wdeps.CheckUnlinkedOpenFiles, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive cycles=%v want 1", got)
	}
	if h.UnlinkedOpenFileBytes != mib(256) || h.UnlinkedOpenFileCount != 2 {
		t.Fatalf("gauges clobbered on PidsOK()=false: bytes=%d count=%d",
			h.UnlinkedOpenFileBytes, h.UnlinkedOpenFileCount)
	}

	// PidsOnce == nil + Proc.PIDs() error must also abort "inconclusive" without zeroing gauges or stamping lastScan.
	h.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := testutil.ToFloat64(h.Cycles.WithLabelValues(wdeps.CheckUnlinkedOpenFiles, "inconclusive")); got != 2 {
		t.Fatalf("inconclusive cycles=%v want 2", got)
	}
	if h.UnlinkedOpenFileBytes != mib(256) || h.UnlinkedOpenFileCount != 2 {
		t.Fatalf("gauges clobbered on Proc.PIDs() error: bytes=%d count=%d",
			h.UnlinkedOpenFileBytes, h.UnlinkedOpenFileCount)
	}

	// Restore /proc without advancing clock: because lastScan was NOT stamped on failure,
	// the recovery sweep runs immediately and updates gauges.
	h.Deps.Proc = procfs.New(e.ProcDir)
	e.MkStatProc(t, 4245, "app", "S", "")
	e.mkDeletedFD(t, 4245, 3, "/var/log/recovered.log")
	e.stubDeletedFDStats(map[string]deletedStat{
		"4245:3": {dev: 100, ino: 44, size: mib(128)},
	})
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := testutil.ToFloat64(h.Cycles.WithLabelValues(wdeps.CheckUnlinkedOpenFiles, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1 (lastScan must not suppress immediate recovery sweep)", got)
	}
	if h.UnlinkedOpenFileBytes != mib(128) || h.UnlinkedOpenFileCount != 1 {
		t.Fatalf("recovered gauges=%d/%d want %d/1",
			h.UnlinkedOpenFileBytes, h.UnlinkedOpenFileCount, mib(128))
	}
}
