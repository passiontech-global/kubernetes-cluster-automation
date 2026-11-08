// ctr_ingest_gc_test.go — the orphan-lease half of the ingest GC:
// leases without a containerd.io/gc.expire label that outlived
// IngestStaleAge pin content blobs the store prune can never drop,
// so the reaper deletes them before the prune runs.
package ctr_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
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
