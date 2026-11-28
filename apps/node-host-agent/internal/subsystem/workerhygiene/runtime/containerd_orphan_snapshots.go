// containerd_orphan_snapshots.go — Wave-7 orphaned containerd overlayfs
// snapshot leak detector (wdeps.CheckOrphanContainerdSnapshots).
//
// Compares WLayerSnapshotsDir entries against live mountinfo upperdirs/lowerdirs,
// containerd snapshots (`k0s ctr -n k8s.io snapshots ls`), active task maps, and
// leases to detect truly orphaned snapshot directories older than
// OrphanSnapshotMinAge and holding >= OrphanSnapshotMinBytes.
//
// Exports Prometheus gauges (node_host_agent_containerd_orphan_snapshot_bytes
// and node_host_agent_containerd_orphan_snapshot_count) and logs a suspect line.
// Deliberately creates no nodecond NodeCondition. Opt-in pruning stays disabled
// by default via NODE_HOST_AGENT_ORPHAN_SNAPSHOT_PRUNE_ENABLED, and when enabled
// obeys HoldLocalAction + cooldown + per-cycle rate budget.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// Package vars so deterministic tests can exercise age/size thresholds.
var (
	OrphanSnapshotMinAge        = 1 * time.Hour
	OrphanSnapshotMinBytes      = int64(64 << 20)
	orphanSnapshotPruneCooldown = 30 * time.Minute
	orphanSnapshotSuspectGap    = 30 * time.Minute
	orphanSnapshotPruneCap      = 10
)

// OrphanContainerdSnapshotsCheck detects (and optionally prunes when enabled)
// orphaned containerd overlayfs snapshot directories on disk.
type OrphanContainerdSnapshotsCheck struct{ d *wdeps.Deps }

// NewOrphanContainerdSnapshots builds the Wave-7 orphan snapshot leak detector.
func NewOrphanContainerdSnapshots(d *wdeps.Deps) *OrphanContainerdSnapshotsCheck {
	return &OrphanContainerdSnapshotsCheck{d: d}
}

// Name returns the check label / WD_SIG key.
func (c *OrphanContainerdSnapshotsCheck) Name() string {
	return wdeps.CheckOrphanContainerdSnapshots
}

type orphanSnapCandidate struct {
	id    string
	path  string
	bytes int64
}

// Run evaluates one containerd-orphan-snapshots pass.
func (c *OrphanContainerdSnapshotsCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckOrphanContainerdSnapshots) {
		return
	}
	snapRoot := c.d.Cfg.Disk.WLayerSnapshotsDir
	entries, err := os.ReadDir(snapRoot)
	if err != nil {
		if os.IsNotExist(err) {
			c.setGauges(0, 0)
			c.d.CycleResult(wdeps.CheckOrphanContainerdSnapshots, "ok")
			return
		}
		c.d.State.SuspectLog(wdeps.CheckOrphanContainerdSnapshots+"-dir",
			fmt.Sprintf("suspect: %s read %s failed: %v — fail closed",
				wdeps.CheckOrphanContainerdSnapshots, snapRoot, err),
			orphanSnapshotSuspectGap)
		c.d.CycleResult(wdeps.CheckOrphanContainerdSnapshots, "abort")
		return
	}

	mountEntries, _, merr := c.d.MountinfoEntries(e)
	if merr != nil {
		c.d.State.SuspectLog(wdeps.CheckOrphanContainerdSnapshots+"-mountinfo",
			fmt.Sprintf("suspect: %s read mountinfo %s failed: %v — fail closed",
				wdeps.CheckOrphanContainerdSnapshots, c.d.Cfg.MountinfoFile, merr),
			orphanSnapshotSuspectGap)
		c.d.CycleResult(wdeps.CheckOrphanContainerdSnapshots, "abort")
		return
	}
	mounted := referencedSnapshotIDs(snapRoot, mountEntries)

	ctrSnaps, serr := c.d.Cfg.Seams.Ctr.Snapshots(ctx)
	if serr != nil {
		c.d.State.SuspectLog(wdeps.CheckOrphanContainerdSnapshots+"-ctr",
			fmt.Sprintf("suspect: %s ctr snapshots ls failed: %v — fail closed",
				wdeps.CheckOrphanContainerdSnapshots, serr),
			orphanSnapshotSuspectGap)
		c.d.CycleResult(wdeps.CheckOrphanContainerdSnapshots, "abort")
		return
	}
	ctrKnown := make(map[string]bool, len(ctrSnaps)*2)
	for _, s := range ctrSnaps {
		if s.Key != "" {
			ctrKnown[s.Key] = true
		}
		if s.Parent != "" {
			ctrKnown[s.Parent] = true
		}
	}
	if e != nil && e.TasksOnce != nil {
		tasks, _ := e.TasksOnce()
		for _, list := range tasks {
			for _, t := range list {
				if t.ID != "" {
					ctrKnown[t.ID] = true
				}
			}
		}
	}
	if leases, lerr := c.d.Cfg.Seams.Ctr.Leases(ctx); lerr == nil {
		for _, l := range leases {
			if l.ID != "" {
				ctrKnown[l.ID] = true
			}
		}
	}

	now := c.d.Cfg.Seams.Host.Clock.Now()
	var orphans []orphanSnapCandidate
	var totalBytes int64
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		id := de.Name()
		if mounted[id] || ctrKnown[id] {
			continue
		}
		snapDir := filepath.Join(snapRoot, id)
		fi, ferr := os.Stat(snapDir)
		if ferr != nil {
			continue
		}
		if now.Sub(fi.ModTime()) < OrphanSnapshotMinAge {
			continue
		}
		size, _ := c.d.WalkBudgeted(e, snapDir)
		if size <= 0 {
			continue
		}
		orphans = append(orphans, orphanSnapCandidate{
			id:    id,
			path:  snapDir,
			bytes: size,
		})
		totalBytes += size
	}

	if len(orphans) == 0 || totalBytes < OrphanSnapshotMinBytes {
		c.setGauges(0, 0)
		c.d.CycleResult(wdeps.CheckOrphanContainerdSnapshots, "ok")
		return
	}

	c.setGauges(totalBytes, len(orphans))
	ids := make([]string, 0, min(len(orphans), 5))
	for i := range min(len(orphans), 5) {
		ids = append(ids, orphans[i].id)
	}
	c.d.State.SuspectLog(wdeps.CheckOrphanContainerdSnapshots,
		fmt.Sprintf("suspect: %s detected %d orphaned containerd snapshot(s) bytes=%d threshold=%d sample=%s",
			wdeps.CheckOrphanContainerdSnapshots, len(orphans), totalBytes, OrphanSnapshotMinBytes, strings.Join(ids, ",")),
		orphanSnapshotSuspectGap)

	if c.d.Cfg.Disk.OrphanSnapshotPruneEnabled && !c.d.HoldLocalAction(ctx) {
		if c.d.State.RateTrySpend("last-orphan-snapshot-prune", orphanSnapshotPruneCooldown) {
			removed, reclaimed := c.pruneOrphans(orphans)
			if removed > 0 {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: %s pruned %d orphaned snapshot(s) reclaimed=%d bytes",
					wdeps.CheckOrphanContainerdSnapshots, removed, reclaimed))
				c.d.Actions.WithLabelValues(wdeps.CheckOrphanContainerdSnapshots, "rm_dir").Inc()
				c.setGauges(totalBytes-reclaimed, len(orphans)-removed)
			}
		}
	}
	c.d.CycleResult(wdeps.CheckOrphanContainerdSnapshots, "ok")
}

func (c *OrphanContainerdSnapshotsCheck) setGauges(bytes int64, count int) {
	if c.d.OrphanSnapshotBytes != nil {
		c.d.OrphanSnapshotBytes.Set(float64(bytes))
	}
	if c.d.OrphanSnapshotCount != nil {
		c.d.OrphanSnapshotCount.Set(float64(count))
	}
}

func (c *OrphanContainerdSnapshotsCheck) pruneOrphans(orphans []orphanSnapCandidate) (removed int, reclaimed int64) {
	for _, o := range orphans {
		if removed >= orphanSnapshotPruneCap {
			break
		}
		if err := os.RemoveAll(o.path); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: %s prune %s failed: %v",
				wdeps.CheckOrphanContainerdSnapshots, o.path, err))
			continue
		}
		removed++
		reclaimed += o.bytes
	}
	return removed, reclaimed
}

// referencedSnapshotIDs collects every snapshot directory ID under snapRoot
// referenced by overlayfs upperdir=, lowerdir=, or workdir= options in mountinfo.
func referencedSnapshotIDs(snapRoot string, entries []wdeps.MountEntry) map[string]bool {
	prefixes := []string{
		strings.TrimRight(fsx.HostSidePath(snapRoot), "/") + "/",
		strings.TrimRight(snapRoot, "/") + "/",
	}
	out := map[string]bool{}
	recordPath := func(raw string) {
		p := procfs.UnescapeMountPath(raw)
		for _, pref := range prefixes {
			if rel, ok := strings.CutPrefix(p, pref); ok {
				if id, _, _ := strings.Cut(rel, "/"); id != "" {
					out[id] = true
				}
			}
		}
	}
	for _, ent := range entries {
		if !ent.HasMount || !ent.HasSep {
			continue
		}
		for opt := range strings.SplitSeq(ent.SuperOpts, ",") {
			switch {
			case strings.HasPrefix(opt, "upperdir="):
				recordPath(strings.TrimPrefix(opt, "upperdir="))
			case strings.HasPrefix(opt, "workdir="):
				recordPath(strings.TrimPrefix(opt, "workdir="))
			case strings.HasPrefix(opt, "lowerdir="):
				for part := range strings.SplitSeq(strings.TrimPrefix(opt, "lowerdir="), ":") {
					recordPath(part)
				}
			}
		}
	}
	return out
}
