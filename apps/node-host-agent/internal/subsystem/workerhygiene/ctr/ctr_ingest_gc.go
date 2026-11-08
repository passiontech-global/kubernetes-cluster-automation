// ctr_ingest_gc.go — the 39/A3 ctr-ingest-gc check: stale containerd
// content ingest dirs reaped above the /var/lib/k0s high watermark
// (or on the 6h rescan cadence), plus the W9 store-wide content
// prune on its own 6h budget while the disk stays high.
package ctr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	contentPruneInterval = 6 * time.Hour // content-store prune budget (Wave-9)
)

// IngestGCCheck is the A3 stale-ingest reaper as a Check; it owns
// the 6h rescan stamp (ex-Hygiene.lastIngestScan).
type IngestGCCheck struct {
	d        *wdeps.Deps
	lastScan time.Time
}

// Name returns the check label / WD_SIG key.
func (c *IngestGCCheck) Name() string { return wdeps.CheckIngestGC }

// Run executes one ctr-ingest-gc round.
func (c *IngestGCCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckIngestGC) {
		return
	}
	var st unix.Statfs_t
	diskHigh := false
	// Free > total wraps uint64 to ~2^64 → used ~= 1.0 → diskHigh
	// permanently true → the GC sweeps EVERY cycle (btrfs/XFS can
	// report Bavail > Blocks). Saturate instead of subtracting
	// blind — same guard as concourse_cache's fsPressure. The
	// free-side field is Bavail, not Bfree: kubelet/containerd run
	// unprivileged against the root-reserved block margin, so
	// unprivileged-free is the signal that trips ENOSPC first.
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.K0sDataDir, &st); err == nil &&
		st.Blocks > 0 && st.Bavail <= st.Blocks {
		used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
		diskHigh = used > c.d.Cfg.Disk.HighWatermark
	}
	due := c.d.Cfg.Seams.Host.Clock.Now().Sub(c.lastScan) >= c.d.Cfg.Ctr.IngestScanInterval
	if !diskHigh && !due {
		c.d.CycleResult(wdeps.CheckIngestGC, "ok")
		return
	}
	// W9: above the high watermark the content store itself may be
	// the hog — run the store-wide prune on its own 6h budget IN
	// ADDITION to the stale-ingest sweep below. Below the
	// watermark (periodic rescan only) it never fires.
	if diskHigh {
		maybePruneContentStore(c.d, ctx)
	}
	entries, err := os.ReadDir(c.d.Cfg.Ctr.IngestDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Absent dir = nothing to scan — stamp like a clean
			// walk so the 6h cadence still applies.
			c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
			c.d.CycleResult(wdeps.CheckIngestGC, "ok")
			return
		}
		// A transient read failure must NOT stamp lastScan —
		// stamping here would defer the retry by a full
		// CtrIngestScanInterval (6h).
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr ingest dir %s unreadable: %v — ingest GC skipped",
			c.d.Cfg.Ctr.IngestDir, err))
		c.d.CycleResult(wdeps.CheckIngestGC, "abort")
		return
	}
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	now := c.d.Cfg.Seams.Host.Clock.Now()
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if n >= c.d.Cfg.Ctr.MaxTaskClean {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr-ingest-gc still pending cap=%d", c.d.Cfg.Ctr.MaxTaskClean))
			break
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		age := now.Sub(fi.ModTime())
		if age < c.d.Cfg.Ctr.IngestMaxAge {
			continue
		}
		ref := e.Name()
		d := filepath.Join(c.d.Cfg.Ctr.IngestDir, ref)
		if rerr := c.d.Cfg.Seams.Ctr.RmIngest(ctx, ref); rerr != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr content ingest rm %s failed: %v — removing dir directly", ref, rerr))
		}
		if _, serr := os.Stat(d); serr == nil {
			if rerr := os.RemoveAll(d); rerr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: rm orphan ingest dir %s failed: %v", d, rerr))
				continue
			}
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: ctr-ingest-gc removed stale ingest %s (age=%.1fh disk_high=%v)",
			ref, age.Hours(), diskHigh))
		n++
		c.d.CtrIngestsCleaned.Inc()
		c.d.Actions.WithLabelValues(wdeps.CheckIngestGC, "ingest_rm").Inc()
	}
	c.d.CycleResult(wdeps.CheckIngestGC, "ok")
}

// maybePruneContentStore runs `k0s ctr -n k8s.io content prune` —
// the store-wide GC that drops content blobs no lease references
// (the stale-ingest sweep only touches ingest/ leftovers; leaked
// leased content is what actually fills /var/lib/k0s). Budgeted by
// the last-content-gc marker at contentPruneInterval — the prune
// walks every blob + lease so it must not run every cycle even
// while the disk stays above the watermark. The budget is spent
// BEFORE the command (rate_spend parity); a failed prune logs
// suspect and does NOT count as an action.
// maybeReapOrphanLeases deletes containerd leases that pin the
// content blobs the prune below would otherwise drop: a lease
// WITHOUT a containerd.io/gc.expire label has no GC lifetime — a
// crashed image pull or interrupted unpack leaves it behind
// forever, and every blob it references survives the store prune.
// Only leases past Cfg.Ctr.IngestStaleAge (2h) are touched — a
// fresh label-less lease may belong to a pull still in flight —
// and the pass is bounded by MaxTaskClean per cycle.
func maybeReapOrphanLeases(d *wdeps.Deps, ctx context.Context) {
	leases, err := d.Cfg.Seams.Ctr.Leases(ctx)
	if err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr-ingest-gc lease list failed: %v", err))
		return
	}
	now := d.Cfg.Seams.Host.Clock.Now()
	n := 0
	for _, l := range leases {
		if l.HasGCExp || l.Created.IsZero() ||
			now.Sub(l.Created) < d.Cfg.Ctr.IngestStaleAge {
			continue
		}
		if n >= d.Cfg.Ctr.MaxTaskClean {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr-ingest-gc orphan leases still pending cap=%d",
				d.Cfg.Ctr.MaxTaskClean))
			break
		}
		if err := d.Cfg.Seams.Ctr.RmLease(ctx, l.ID); err != nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: ctr-ingest-gc lease rm %s failed: %v", l.ID, err))
			continue
		}
		d.State.AppendLog(fmt.Sprintf(
			"ACTION: ctr-ingest-gc reaped orphan lease %s (age=%.1fh, no gc.expire label)",
			l.ID, now.Sub(l.Created).Hours()))
		d.Actions.WithLabelValues(wdeps.CheckIngestGC, "lease_rm").Inc()
		n++
	}
}

func maybePruneContentStore(d *wdeps.Deps, ctx context.Context) {
	// Lease reaper FIRST: an orphan lease pins the blobs the prune
	// would drop — reaping it lets this GC pass actually reclaim.
	maybeReapOrphanLeases(d, ctx)
	if !d.State.RateTrySpend("last-content-gc", contentPruneInterval) {
		return
	}
	if err := d.Cfg.Seams.Ctr.PruneContent(ctx); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr-ingest-gc content prune failed: %v", err))
		return
	}
	d.State.AppendLog("ACTION: ctr-ingest-gc content prune ran (disk above watermark)")
	d.Actions.WithLabelValues(wdeps.CheckIngestGC, "content_gc").Inc()
}
