// orphan_hostpath.go — the orphaned hostPath volume dir reaper:
// pvc-* dirs under the local-provisioner roots whose PV is gone.
// Split out of deep_failure_checks.go.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// orphanHostPathMinAge is the ST2 grace period — a pvc-* dir younger
// than this may belong to a PV the apiserver hasn't finished
// deleting (or one about to be created).
const orphanHostPathMinAge = 24 * time.Hour

// --- orphan-hostpath: orphaned hostPath volume dirs ---

// orphanHPCacheTTL bounds the live-PV-name cache — the LIST is
// cluster-scope and every worker pays it every cycle for a handful
// of pvc-* dirs. 30m staleness is safe: the 24h dir-age gate keeps
// fresh dirs out of the removal path regardless.
const orphanHPCacheTTL = 30 * time.Minute

// OrphanHPCheck finds pvc-* dirs under the local-provisioner roots
// whose PersistentVolume is gone from the apiserver — the disk leak
// a deleted PV leaves behind (the provisioner removes the PV
// object; the hostPath dir is its problem). Metrics always report
// confirmed orphans; removal is deliberately narrow: dir mtime
// >24h (deletion grace), backing filesystem >80% used, and the dir
// EMPTY or holding only a ".deleted" marker — anything with real
// data is reported, never touched. An apiserver LIST failure makes
// "PV not found" unverifiable → the whole removal half stands down
// (metrics keep their last values). The gauge values live on
// deps (orphanHostPathBytes/Dirs) — writeNodeAgentPromTextfile
// reads them at end of Cycle.
type OrphanHPCheck struct {
	d *wdeps.Deps
	// orphanPVNames/orphanPVAt cache the live PV-name set for
	// orphanHPCacheTTL so the cluster-scope LIST does not run every
	// cycle (W19-HP1). A stale entry only delays detecting a
	// brand-new PV by one refresh — the 24h dir-age gate covers it.
	orphanPVNames map[string]bool
	orphanPVAt    time.Time
}

// Name returns the check label / WD_SIG key.
func (c *OrphanHPCheck) Name() string { return wdeps.CheckOrphanHP }

// Run executes one orphan-hostpath round.
func (c *OrphanHPCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckOrphanHP) {
		return
	}
	type cand struct {
		path, name string
	}
	var cands []cand
	for _, root := range c.d.Cfg.Disk.OrphanHostPathDirs {
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "pvc-") {
				continue
			}
			cands = append(cands, cand{
				path: filepath.Join(root, e.Name()), name: e.Name()})
		}
	}
	if len(cands) == 0 || c.d.Cfg.Client == nil {
		// Nothing to verify — a cluster-scope PV LIST on every
		// worker every cycle for zero candidates is wasted
		// apiserver traffic (and a nil client, defensive only —
		// New rejects it — would nil-pointer panic). Zero the
		// gauges too so a dir set deleted since the last real
		// scan can't leave stale counts behind.
		c.d.OrphanHostPathDirs = 0
		c.d.OrphanHostPathBytes = 0
		c.d.CycleResult(wdeps.CheckOrphanHP, "ok")
		return
	}
	// W19-HP1 fast path: when the PV-name cache is fresh AND every
	// local pvc-* dir maps to a live PV, there can be no orphan —
	// clear the gauges and skip both the apiserver LIST and the
	// per-dir stat/walk entirely.
	pvCacheFresh := !c.orphanPVAt.IsZero() &&
		c.d.Cfg.Seams.Host.Clock.Now().Sub(c.orphanPVAt) < orphanHPCacheTTL
	if pvCacheFresh {
		allKnown := true
		for _, cd := range cands {
			if !orphanHPKnownPV(c.orphanPVNames, cd.name) {
				allKnown = false
				break
			}
		}
		if allKnown {
			c.d.OrphanHostPathBytes = 0
			c.d.OrphanHostPathDirs = 0
			c.d.CycleResult(wdeps.CheckOrphanHP, "ok")
			return
		}
	}
	// Any dir the cache does NOT know might be a PV created inside
	// the cache window — acting on the stale set could delete a
	// live volume's hostPath. Only the all-known fast path above
	// trusts the cache; every other cycle pays a fresh LIST.
	pvNames := map[string]bool{}
	apiOK := true
	// ResourceVersion "0" = quorum read from cache — a full
	// etcd-backed LIST on every refresh would re-serialize the
	// whole PV table per worker per cycle.
	pvs, err := c.d.Cfg.Client.CoreV1().PersistentVolumes().
		List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		apiOK = false
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: orphan-hostpath PV list failed: %v — removal half inconclusive",
			err))
	} else {
		for _, pv := range pvs.Items {
			pvNames[pv.Name] = true
		}
		c.orphanPVNames = pvNames
		c.orphanPVAt = c.d.Cfg.Seams.Host.Clock.Now()
	}
	var totalBytes int64
	orphans := 0
	for _, cd := range cands {
		if orphanHPKnownPV(pvNames, cd.name) {
			continue
		}
		if !apiOK {
			continue // can't confirm "PV gone" — not an orphan yet
		}
		orphans++
		size, _ := c.d.WalkBytes(cd.path)
		totalBytes += size
		fi, err := os.Stat(cd.path)
		if err != nil {
			continue
		}
		if c.d.Cfg.Seams.Host.Clock.Now().Sub(fi.ModTime()) < orphanHostPathMinAge {
			continue // inside the deletion grace window
		}
		if !c.d.DiskUsageAboveWatermark(filepath.Dir(cd.path)) {
			continue // disk pressure gate — keep the evidence
		}
		if ok, why := orphanHPRemovable(cd.path); ok {
			if rerr := os.RemoveAll(cd.path); rerr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: orphan-hostpath remove %s failed: %v", cd.path, rerr))
			} else {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: removed orphaned hostpath volume dir %s (%s, %d bytes)",
					cd.path, why, size))
				c.d.Actions.WithLabelValues(wdeps.CheckOrphanHP, "rm_dir").Inc()
			}
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan hostpath %s holds data (%s, %d bytes) — left in place",
				cd.path, why, size))
		}
	}
	if apiOK {
		c.d.OrphanHostPathBytes = totalBytes
		c.d.OrphanHostPathDirs = orphans
	}
	c.d.CycleResult(wdeps.CheckOrphanHP, "ok")
}

// checkOrphanedHostPathVolumes forwards to the migrated Check —
// tests written before the interface still call the old method
// shape.

// orphanHPKnownPV reports whether a pvc-* dir name still maps to a
// live PV — exact match plus the trimmed-uuid variants provisioners
// use (dir "pvc-<uuid>" ↔ PV "pvc-<uuid>"; some name the PV without
// the pvc- prefix).
func orphanHPKnownPV(pvNames map[string]bool, dirName string) bool {
	if pvNames[dirName] {
		return true
	}
	trimmed := strings.TrimPrefix(dirName, "pvc-")
	return pvNames[trimmed] || pvNames["pvc-"+trimmed]
}

// orphanHPRemovable reports whether an orphan dir is safe to delete:
// completely empty, or containing ONLY a ".deleted" marker file
// (the local-path provisioner's tombstone). Anything else holds
// potential data and is reported, never removed.
func orphanHPRemovable(dir string) (bool, string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, "unreadable: " + err.Error()
	}
	if len(ents) == 0 {
		return true, "empty"
	}
	if len(ents) == 1 && ents[0].Name() == ".deleted" && ents[0].Type().IsRegular() {
		return true, "deleted-marker"
	}
	return false, fmt.Sprintf("%d entries", len(ents))
}
