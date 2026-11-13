// coredump_gc.go — disk side-guard promoted out of DiskBloatCheck into
// its own wdeps.Check (wdeps.CheckCoredumpGC): per-guard WD_SIG kill
// switch, cycles{check,result} series and action labels. The
// guard body is unchanged — it always ran on the shared *wdeps.Deps.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type CoredumpGCCheck struct{ d *wdeps.Deps }

// NewCoredumpGC builds the coredump disk guard check.
func NewCoredumpGC(d *wdeps.Deps) *CoredumpGCCheck { return &CoredumpGCCheck{d: d} }

// Name returns the check label / WD_SIG key.
func (c *CoredumpGCCheck) Name() string { return wdeps.CheckCoredumpGC }

// Run executes one coredump round under its own gate.
func (c *CoredumpGCCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCoredumpGC) {
		return
	}
	c.coredumpGC()
	c.d.CycleResult(wdeps.CheckCoredumpGC, "ok")
}

// --- Coredump-storm guard + overlayfs writable-layer scan ---

// coredumpGC sweeps stale core dumps under CoredumpDir once the
// filesystem holding it crosses the disk-bloat warn watermark (the
// same evidence source the disk-bloat walk gates on). The coredump
// Storage=none drop-in keeps a converged host's store empty; this is
// the backstop for nodes the drop-in has not reached yet. Files
// younger than coredumpMinAge survive one cycle so an in-progress
// core write is never truncated mid-sweep.
func (c *CoredumpGCCheck) coredumpGC() {
	dir := c.d.Cfg.Disk.CoredumpDir
	if dir == "" {
		return
	}
	var st unix.Statfs_t
	if err := c.d.Cfg.Seams.Host.StatfsFn(dir, &st); err != nil ||
		st.Blocks <= 0 || st.Bavail > st.Blocks {
		return // inconclusive — never sweep on garbage statfs
	}
	used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
	if used <= c.d.Cfg.Disk.BloatWatermark {
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	type coreFile struct {
		path string
		mod  time.Time
	}
	var stale []coreFile
	for _, ent := range ents {
		if !ent.Type().IsRegular() {
			continue
		}
		fi, err := ent.Info()
		if err != nil || now.Sub(fi.ModTime()) < coredumpMinAge {
			continue
		}
		stale = append(stale, coreFile{
			path: filepath.Join(dir, ent.Name()),
			mod:  fi.ModTime(),
		})
	}
	// Oldest first — a capped sweep drains the oldest evidence
	// deterministically instead of ReadDir-order.
	slices.SortFunc(stale, func(a, b coreFile) int { return a.mod.Compare(b.mod) })
	removed := 0
	for _, f := range stale {
		if removed >= coredumpSweepMax {
			break // bound one cycle's blast radius — parity with runTmpfsSweepMax
		}
		if err := os.Remove(f.path); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: disk-bloat coredump rm %s failed: %v", f.path, err))
			continue
		}
		removed++
	}
	if removed == 0 {
		return
	}
	line := fmt.Sprintf(
		"ACTION: disk-bloat coredump sweep — removed %d stale core files from %s (used %.1f%%)",
		removed, dir, used*100)
	if drained := len(stale) - removed; drained > 0 {
		line += fmt.Sprintf(" — cap %d reached, %d remaining drain next cycle",
			coredumpSweepMax, drained)
	}
	c.d.State.AppendLog(line)
	c.d.Actions.WithLabelValues(wdeps.CheckCoredumpGC, "coredump_rm").Inc()
}

// podDeclaresEphemeralStorage reports whether ANY container of the
// pod (init + regular) pins a limits.ephemeral-storage value — the
// pods the writable-layer scan may legitimately leave alone (their
// writable layers are already bounded by the kubelet eviction chain).
func podDeclaresEphemeralStorage(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for i := range pod.Spec.InitContainers {
		if _, ok := pod.Spec.InitContainers[i].Resources.Limits[corev1.ResourceEphemeralStorage]; ok {
			return true
		}
	}
	for i := range pod.Spec.Containers {
		if _, ok := pod.Spec.Containers[i].Resources.Limits[corev1.ResourceEphemeralStorage]; ok {
			return true
		}
	}
	return false
}

// writableLayerScan is the runaway writable-layer detector:
// a container WITHOUT a limits.ephemeral-storage bound can grow its
// overlayfs upperdir until the node falls into DiskPressure — the
// one write surface the kubelet's eviction chain never measures.
// The scan walks (a) the active overlayfs snapshotter's <id>/fs
// upperdirs and (b) the kubelet pod volume dirs of pods lacking the
// limit; any writable layer past WLayerBloatThresholdBytes (5 GiB —
// deliberately tighter than the disk-bloat eviction threshold) raises a
// ContainerWritableLayerBloat Warning event (on the owning pod when
// the snapshot/pod dir resolves, else node-scoped). It is
// interval-budgeted (BloatScanInterval) because the size walk is IO
// on the very disk that is filling.
