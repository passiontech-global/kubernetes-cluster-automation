package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- A3: ingest GC ---

func TestCtrIngestGCCleansStaleDirs(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.DiskUsed = 0.90 // above the 75% watermark
	stale := filepath.Join(e.IngestDir, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale ingest dir should be removed, stat err=%v", err)
	}
	if !e.SDRan("content ingest rm deadbeefref") {
		t.Fatal("ctr ingest rm should run for the stale ref")
	}
	got, err := counterValue(e.H.CtrIngestsCleaned)
	if err != nil || got != 1 {
		t.Fatalf("ctr_ingests_cleaned_total=%v err=%v want 1", got, err)
	}
}

func TestCtrIngestGCSkipsFreshDirsWhenDiskLow(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.DiskUsed = 0.10
	// first cycle marks lastIngestScan (due on start); make a fresh
	// dir and verify a second cycle under low disk skips it.
	e.H.Cycle(context.Background())
	fresh := filepath.Join(e.IngestDir, "stillpulling")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh ingest dir must not be removed")
	}
}

// TestCtrIngestGCFailedScanRetriesNextCycle: a transient ReadDir
// failure must NOT stamp lastIngestScan — stamping would defer the
// retry by a full 6h CtrIngestScanInterval. The next cycle after
// the dir recovers must still scan (disk below the watermark, so
// only the unstamped due-check lets it in).
func TestCtrIngestGCFailedScanRetriesNextCycle(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.DiskUsed = 0.10 // below watermark — only `due` triggers a scan
	// Break the ingest dir: a plain FILE where a dir is expected →
	// ReadDir errors (ENOTDIR, not IsNotExist) → abort, no stamp.
	if err := os.RemoveAll(e.IngestDir); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, e.IngestDir, "not a dir")
	e.H.Cycle(context.Background())
	// Repair the dir with one stale ingest — if the failed scan
	// had stamped lastIngestScan this cycle would be not-due and
	// skip the cleanup.
	if err := os.Remove(e.IngestDir); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(e.IngestDir, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("failed scan must not defer retry — stale dir should be removed, stat err=%v", err)
	}
}

// TestCtrIngestGCBavailOverBlocksSaturates: btrfs/XFS can report
// Bavail > Blocks — the uint64 subtraction wraps to ~2^64 and
// diskHigh sticks true, sweeping the GC every cycle. The saturation
// guard must keep it low (concourse fsPressure parity).
func TestCtrIngestGCBavailOverBlocksSaturates(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.H.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks, st.Bavail = 100, 120 // free > total
		return nil
	}
	// First cycle stamps lastIngestScan so the second is not `due`.
	e.H.Cycle(context.Background())
	stale := filepath.Join(e.IngestDir, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("stale ingest dir swept under wrapped-free disk pressure")
	}
}

// counterValue reads a prometheus.Counter for tests.
func counterValue(c prometheus.Counter) (float64, error) {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0, err
	}
	return m.GetCounter().GetValue(), nil
}
