// ctr_ingest_gc_test.go — the orphan-lease half of the ingest GC:
// leases without a containerd.io/gc.expire label that outlived
// IngestStaleAge pin content blobs the store prune can never drop,
// so the reaper deletes them before the prune runs.
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

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// leaseTable renders one `ctr leases ls` output row.
func leaseTable(id, created string, labels string) string {
	return fmt.Sprintf("%-30s %s %s\n", id, created, labels)
}

func TestCtrIngestGCOrphanLeases(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.9 // above the high watermark -> prune branch runs
	stamp := func(ago time.Duration) string {
		return e.Now.Add(-ago).UTC().Format("2006-01-02 15:04:05") + " +0000 UTC"
	}
	e.SDReply["k0s ctr -n k8s.io leases ls"] =
		"ID                            CREATED AT                    LABELS\n" +
			leaseTable("moby.orphan1", stamp(3*time.Hour), "") +
			leaseTable("moby.young", stamp(30*time.Minute), "") +
			leaseTable("moby.expiring", stamp(3*time.Hour), "containerd.io/gc.expire=1700000000")

	e.H.Cycle(context.Background())

	if !e.SDRan("leases rm moby.orphan1") {
		t.Fatalf("orphan lease not reaped:\n%s", e.LogLines(t))
	}
	if e.SDRan("leases rm moby.young") {
		t.Fatal("fresh label-less lease reaped — age gate broken")
	}
	if e.SDRan("leases rm moby.expiring") {
		t.Fatal("lease with gc.expire label reaped — label filter broken")
	}
	if log := e.LogLines(t); !strings.Contains(log, "reaped orphan lease moby.orphan1") {
		t.Fatalf("watchdog log missing reaped-lease ACTION:\n%s", log)
	}
}

// --- scan gates, caps and prune tails ---

// staleIngestDir lays down an ingest dir with an mtime ageOld.
func staleIngestDir(t *testing.T, e *env, ref string, ageOld time.Duration) string {
	t.Helper()
	d := filepath.Join(e.IngestDir, ref)
	wdepstest.WriteFile(t, filepath.Join(d, "blob"), "x")
	old := e.Now.Add(-ageOld)
	if err := os.Chtimes(d, old, old); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestCtrIngestGCDueRescanCapsAndSkipsFresh: the 6h rescan fires
// below the watermark on a fresh check, stale dirs drain at
// MaxTaskClean per cycle, fresh dirs and non-dir entries stay.
func TestCtrIngestGCDueRescanCapsAndSkipsFresh(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.10 // below the watermark — only `due` lets it in
	e.H.Cfg.Ctr.MaxTaskClean = 1
	stale1 := staleIngestDir(t, e, "ref-stale-1", 4*time.Hour)
	stale2 := staleIngestDir(t, e, "ref-stale-2", 4*time.Hour)
	fresh := filepath.Join(e.IngestDir, "ref-fresh")
	wdepstest.WriteFile(t, filepath.Join(fresh, "blob"), "x")
	wdepstest.WriteFile(t, filepath.Join(e.IngestDir, "a-file"), "not a dir")

	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale1); !os.IsNotExist(err) {
		t.Fatal("first stale ref not reaped on the due rescan")
	}
	if _, err := os.Stat(stale2); err != nil {
		t.Fatal("second stale reaped over the per-cycle cap")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh ingest dir reaped before its age")
	}
	if _, err := os.Stat(filepath.Join(e.IngestDir, "a-file")); err != nil {
		t.Fatal("non-dir ingest entry removed")
	}
	if !e.SDRan("content ingest rm ref-stale-1") {
		t.Fatalf("no ctr ingest rm for the stale ref:\n%s", e.LogLines(t))
	}
	if !strings.Contains(e.LogLines(t), "still pending cap=1") {
		t.Fatalf("missing cap suspect line:\n%s", e.LogLines(t))
	}
}

// TestCtrIngestGCMissingDirStampsQuietly: an absent ingest dir is a
// clean walk — it stamps lastScan so the 6h cadence holds.
func TestCtrIngestGCMissingDirStampsQuietly(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.10
	e.H.Cfg.Ctr.IngestDir = filepath.Join(e.IngestDir, "missing")

	e.H.Cycle(context.Background())
	// The dir appears between cycles — inside the 6h cadence the
	// stamped rescan must not fire.
	wdepstest.WriteFile(t, filepath.Join(e.H.Cfg.Ctr.IngestDir, "late", "blob"), "x")
	old := e.Now.Add(-4 * time.Hour)
	if err := os.Chtimes(filepath.Join(e.H.Cfg.Ctr.IngestDir, "late"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if strings.Contains(e.LogLines(t), "removed stale ingest") {
		t.Fatalf("scan fired inside the stamped cadence:\n%s", e.LogLines(t))
	}
}

// TestCtrIngestGCReadErrorAbortsAndRetries: a transient read failure
// must NOT stamp lastScan — the next cycle retries immediately.
func TestCtrIngestGCReadErrorAbortsAndRetries(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.10
	notADir := filepath.Join(e.IngestDir, "busy")
	wdepstest.WriteFile(t, notADir, "x")
	e.H.Cfg.Ctr.IngestDir = notADir

	e.H.Cycle(context.Background())
	if n := strings.Count(e.LogLines(t), "ingest GC skipped"); n != 1 {
		t.Fatalf("unreadable-dir suspect lines=%d want 1:\n%s", n, e.LogLines(t))
	}
	e.H.Cycle(context.Background()) // retried, not deferred by a stamp
	if n := strings.Count(e.LogLines(t), "ingest GC skipped"); n != 2 {
		t.Fatalf("scan was stamped by a failed walk — no retry: %d lines", n)
	}
}

// TestCtrIngestGCRmFailureFallsBackToRemoveAll: a failed ctr exec
// still reclaims the bytes — the dir is removed directly.
func TestCtrIngestGCRmFailureFallsBackToRemoveAll(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.90
	stale := staleIngestDir(t, e, "ref-stuck", 4*time.Hour)
	e.H.Cfg.Seams.Ctr.Exec = func(context.Context, ...string) error {
		return errors.New("ctr unavailable")
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale ingest dir kept after the ctr rm failed")
	}
	if !strings.Contains(e.LogLines(t), "failed: ctr unavailable — removing dir directly") {
		t.Fatalf("missing fallback line:\n%s", e.LogLines(t))
	}
}

// TestCtrIngestGCLeaseListErrorStillPrunes: an unreadable lease list
// is inconclusive for the reaper but must not eat the prune budget.
func TestCtrIngestGCLeaseListErrorStillPrunes(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.90
	e.H.Cfg.Seams.Ctr.ExecOut = func(context.Context, ...string) (string, error) {
		return "", errors.New("leases ls unavailable")
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "lease list failed") {
		t.Fatalf("missing lease-list suspect line:\n%s", e.LogLines(t))
	}
	if !e.SDRan("content prune") {
		t.Fatal("the store prune never ran — the lease outage ate the budget")
	}
}

// TestCtrIngestGCLeaseRmFailureContinues: one failing lease rm must
// not stop the reaper — the next orphan is still attempted.
func TestCtrIngestGCLeaseRmFailureContinues(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.90
	stamp := func(ago time.Duration) string {
		return e.Now.Add(-ago).UTC().Format("2006-01-02 15:04:05") + " +0000 UTC"
	}
	e.SDReply["k0s ctr -n k8s.io leases ls"] =
		leaseTable("moby.first", stamp(3*time.Hour), "") +
			leaseTable("moby.second", stamp(3*time.Hour), "")
	orig := e.H.Cfg.Seams.Ctr.Exec // records argv, answers success
	e.H.Cfg.Seams.Ctr.Exec = func(ctx context.Context, argv ...string) error {
		if err := orig(ctx, argv...); err != nil {
			return err
		}
		if strings.Contains(strings.Join(argv, " "), "leases rm moby.first") {
			return errors.New("lease gone")
		}
		return nil
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "lease rm moby.first failed") {
		t.Fatalf("missing lease-rm suspect line:\n%s", e.LogLines(t))
	}
	if !e.SDRan("leases rm moby.second") {
		t.Fatal("reaper stopped at the first failed lease")
	}
}

// TestCtrIngestGCLeaseCapBoundsThePass: MaxTaskClean bounds the
// orphan-lease reaper like every other sweep.
func TestCtrIngestGCLeaseCapBoundsThePass(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.90
	e.H.Cfg.Ctr.MaxTaskClean = 1
	stamp := e.Now.Add(-3*time.Hour).UTC().Format("2006-01-02 15:04:05") + " +0000 UTC"
	e.SDReply["k0s ctr -n k8s.io leases ls"] =
		leaseTable("moby.cap1", stamp, "") +
			leaseTable("moby.cap2", stamp, "")
	e.H.Cycle(context.Background())
	if !e.SDRan("leases rm moby.cap1") {
		t.Fatal("first orphan lease not reaped")
	}
	if e.SDRan("leases rm moby.cap2") {
		t.Fatal("second lease reaped over the per-cycle cap")
	}
	if !strings.Contains(e.LogLines(t), "orphan leases still pending cap=1") {
		t.Fatalf("missing lease-cap line:\n%s", e.LogLines(t))
	}
}

// TestCtrIngestGCPruneFailureConsumesItsBudget: a failed prune logged
// its suspect and the 6h budget is spent — the next in-window cycle
// must not exec the prune again.
func TestCtrIngestGCPruneFailureConsumesItsBudget(t *testing.T) {
	e := fixture(t)
	e.DiskUsed = 0.90
	e.H.Cfg.Seams.Ctr.Exec = func(context.Context, ...string) error {
		return errors.New("prune failed")
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "content prune failed") {
		t.Fatalf("missing prune-failure suspect line:\n%s", e.LogLines(t))
	}
	e.H.Cfg.Seams.Ctr.Exec = func(context.Context, ...string) error {
		t.Error("prune exec ran again inside its 6h budget")
		return nil
	}
	e.H.Cycle(context.Background())
}

// TestCtrIngestGCGated: the worker gate stands the GC down — no stat
// call, no scan, no prune.
func TestCtrIngestGCGated(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		t.Error("statfs ran with the worker gate down")
		return nil
	}
	wdepstest.Check[*ctr.IngestGCCheck](e.H, wdeps.CheckIngestGC).
		Run(context.Background(), &wdeps.CycleEnv{})
}
