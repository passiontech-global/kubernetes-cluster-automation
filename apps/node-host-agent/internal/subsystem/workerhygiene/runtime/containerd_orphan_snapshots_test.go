package runtime_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	whruntime "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func seedSnapshotDir(t *testing.T, root, id, content string, mtime time.Time) string {
	t.Helper()
	dir := filepath.Join(root, id)
	f := filepath.Join(dir, "fs", "blob")
	wdepstest.WriteFile(t, f, content)
	if err := os.Chtimes(dir, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOrphanContainerdSnapshotsDetectAndAgeAndThreshold(t *testing.T) {
	oldMinBytes := whruntime.OrphanSnapshotMinBytes
	whruntime.OrphanSnapshotMinBytes = 50
	t.Cleanup(func() { whruntime.OrphanSnapshotMinBytes = oldMinBytes })

	e := fixture(t)
	snapRoot := filepath.Join(t.TempDir(), "snapshots")
	e.H.Cfg.Disk.WLayerSnapshotsDir = snapRoot
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")

	now := e.Now
	oldTime := now.Add(-2 * time.Hour)
	freshTime := now.Add(-15 * time.Minute)

	// Mounted upperdir -> live (not orphan).
	seedSnapshotDir(t, snapRoot, "10", strings.Repeat("a", 100), oldTime)
	// Known in `ctr -n k8s.io snapshots ls` -> live (not orphan).
	seedSnapshotDir(t, snapRoot, "20", strings.Repeat("b", 100), oldTime)
	// Fresh (< OrphanSnapshotMinAge) -> skipped.
	seedSnapshotDir(t, snapRoot, "30", strings.Repeat("c", 100), freshTime)
	// Aged unmounted & absent from ctr snapshots -> ORPHAN (100 bytes).
	orphanDir := seedSnapshotDir(t, snapRoot, "99", strings.Repeat("x", 100), oldTime)

	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile,
		"100 1 0:50 / /var/lib/k0s/containerd/io.containerd.runtime.v2.task/k8s.io/t1/rootfs rw - overlay overlay rw,upperdir="+snapRoot+"/10/fs,lowerdir="+snapRoot+"/20/fs\n")

	e.H.Cfg.Seams.Ctr.ExecOut = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) >= 5 && argv[3] == "snapshots" {
			return "KEY\tPARENT\tKIND\n20\t-\tCommitted\n", nil
		}
		return "", nil
	}

	chk := e.H.Check(wdeps.CheckOrphanContainerdSnapshots)
	ce := &wdeps.CycleEnv{WorkerActive: true}
	chk.Run(context.Background(), ce)

	if got := promtestutil.ToFloat64(e.H.OrphanSnapshotCount); got != 1 {
		t.Fatalf("orphan count = %v, want 1", got)
	}
	if got := promtestutil.ToFloat64(e.H.OrphanSnapshotBytes); got != 100 {
		t.Fatalf("orphan bytes = %v, want 100", got)
	}
	logs := e.LogLines(t)
	if !strings.Contains(logs, "suspect: containerd-orphan-snapshots detected 1 orphaned containerd snapshot(s)") {
		t.Fatalf("missing suspect log:\n%s", logs)
	}
	// Default OrphanSnapshotPruneEnabled=false: orphan directory must NOT be deleted.
	if _, err := os.Stat(orphanDir); err != nil {
		t.Fatalf("orphan dir should not be pruned when prune is disabled: %v", err)
	}
}

func TestOrphanContainerdSnapshotsFailClosedOnCtrErr(t *testing.T) {
	e := fixture(t)
	snapRoot := filepath.Join(t.TempDir(), "snapshots")
	e.H.Cfg.Disk.WLayerSnapshotsDir = snapRoot
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "")
	seedSnapshotDir(t, snapRoot, "99", strings.Repeat("x", 100), e.Now.Add(-2*time.Hour))

	e.H.Cfg.Seams.Ctr.ExecOut = func(context.Context, ...string) (string, error) {
		return "", errors.New("containerd unavailable")
	}
	chk := e.H.Check(wdeps.CheckOrphanContainerdSnapshots)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckOrphanContainerdSnapshots, "abort")); got != 1 {
		t.Fatalf("expected abort when ctr snapshots ls errors, got %v", got)
	}
}

func TestOrphanContainerdSnapshotsOptInPruneAndMaintenanceHold(t *testing.T) {
	oldMinBytes := whruntime.OrphanSnapshotMinBytes
	whruntime.OrphanSnapshotMinBytes = 50
	t.Cleanup(func() { whruntime.OrphanSnapshotMinBytes = oldMinBytes })

	e := fixture(t)
	snapRoot := filepath.Join(t.TempDir(), "snapshots")
	e.H.Cfg.Disk.WLayerSnapshotsDir = snapRoot
	e.H.Cfg.Disk.OrphanSnapshotPruneEnabled = true
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "")
	orphanDir := seedSnapshotDir(t, snapRoot, "99", strings.Repeat("x", 100), e.Now.Add(-2*time.Hour))

	e.H.Cfg.Seams.Ctr.ExecOut = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) >= 5 && argv[3] == "snapshots" {
			return "KEY\tPARENT\tKIND\n", nil
		}
		return "", nil
	}

	// Under cluster maintenance hold -> HoldLocalAction suppresses prune.
	hold := true
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			if hold {
				return map[string]string{nodecond.KuredLockAnno: `{"nodeID":"node-a"}`}, nil
			}
			return nil, nil
		},
	}
	chk := e.H.Check(wdeps.CheckOrphanContainerdSnapshots)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if _, err := os.Stat(orphanDir); err != nil {
		t.Fatalf("orphan dir pruned despite HoldLocalAction: %v", err)
	}

	// Clear hold and advance past Coord's 30s annotation cache TTL -> opt-in prune executes and zeroes gauges.
	hold = false
	e.Now = e.Now.Add(time.Minute)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		t.Fatalf("expected orphan dir pruned, stat err=%v", err)
	}
	if !strings.Contains(e.LogLines(t), "ACTION: containerd-orphan-snapshots pruned 1 orphaned snapshot(s)") {
		t.Fatalf("missing prune ACTION log:\n%s", e.LogLines(t))
	}
	if got := promtestutil.ToFloat64(e.H.OrphanSnapshotCount); got != 0 {
		t.Fatalf("post-prune orphan count = %v, want 0", got)
	}
}
