// sweep.go — the sweep orchestration: the pvc-*/shared-cache walk,
// the per-cache prune order, fs-pressure escalation (statfs →
// high/crit tightened limits) and the one-level ownership/perm
// invariant enforced before pruning.
package concoursecache

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/concourse"
)

// Sweep runs one prune pass over every pvc-*/shared-cache under
// openebsRoot. The name check is the orphan sweeper's strict
// pvc-<uuid> belt (pvcNameRe) — a hand-made pvc-* dir or a stray
// pvc-* file is not a worker volume and gets no chown/chmod/prune.
// Non-matching dirs and pvc dirs without a shared-cache are skipped
// (the script's `[ -d "$SC" ] || exit 0`).
func (p *Pruner) Sweep(ctx context.Context, openebsRoot string) error {
	entries, err := os.ReadDir(openebsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			p.cycles.WithLabelValues("ok").Inc()
			return nil
		}
		p.cycles.WithLabelValues("abort").Inc()
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			p.cycles.WithLabelValues("abort").Inc()
			return err
		}
		if !e.IsDir() || !pvcNameRe.MatchString(e.Name()) {
			continue
		}
		p.pruneSharedCache(ctx,
			filepath.Join(openebsRoot, e.Name(), concourse.SharedCacheName))
	}
	p.cycles.WithLabelValues("ok").Inc()
	return nil
}

// pruneSharedCache applies every bucket rule to one shared-cache dir,
// in the script's order. All helpers are best-effort (the script's
// `2>/dev/null || true`) — only ctx cancellation aborts mid-flight.
func (p *Pruner) pruneSharedCache(ctx context.Context, sc string) {
	log := logger().With("subsystem", "concourse-cache", "dir", sc)
	if !isDir(sc) {
		return // init-rm not done yet — nothing to prune
	}
	p.enforcePerms(sc, log)
	eff := p.escalatedLimits(sc, log)

	// go-build: stale entries + its own size cap.
	p.pruneGoBuild(ctx, sc, eff, log)

	// Artifact bus: 24h files + empty dirs, then the build <key> cap.
	for _, b := range []string{"build", "coverage"} {
		p.pruneAgeBucket(ctx, sc, b, eff.ArtifactMaxAge, true, log)
	}
	p.capTopLevelDirs(ctx, sc, "build",
		eff.BuildHighMark, eff.BuildLowMark, false, log)

	// affected + ytt: 48h files, no dir cleanup.
	for _, b := range []string{"affected", "ytt"} {
		p.pruneAgeBucket(ctx, sc, b, eff.StaleMaxAge, false, log)
	}
	// nx + moon task-graph caches: 7d files + empty dirs.
	for _, b := range []string{"nx", "moon"} {
		p.pruneAgeBucket(ctx, sc, b, eff.GraphMaxAge, true, log)
	}
	// Scanner/tool caches: 14d files + empty dirs.
	for _, b := range []string{"trivy", "sonar", "golangci-lint",
		"uv", "pip", "bin", "py-tools", "bun"} {
		p.pruneAgeBucket(ctx, sc, b, eff.ToolMaxAge, true, log)
	}
	p.pruneNodeDeps(ctx, sc, eff, log)
}

// fsPressure returns the used percent of the filesystem holding
// path — the max of the block and inode ratios. Inode exhaustion
// (hundreds of thousands of tiny cache files) trips ENOSPC long
// before the byte count looks full, so either signal must escalate
// the prune. ok=false when statfs fails — the caller keeps the
// normal limits.
func (p *Pruner) fsPressure(path string) (pct float64, ok bool) {
	var st syscall.Statfs_t
	if err := p.cfg.statfsFn(path, &st); err != nil {
		return 0, false
	}
	var diskPct, inodePct float64
	// Free > total wraps uint64 to ~2^64 → a bogus ratio that would
	// escalate to crit on a healthy fs (btrfs/XFS can report this).
	// Saturate instead of subtracting blind. The free-side field is
	// Bavail, not Bfree — blocks reserved for root don't count as
	// usable by the unprivileged task-container writers this prune
	// protects, so unprivileged-free is the safer signal (the same
	// choice workerhygiene's ctr-ingest-GC disk trigger makes).
	if st.Blocks > 0 && st.Bavail <= st.Blocks {
		diskPct = float64(st.Blocks-st.Bavail) / float64(st.Blocks) * 100
	}
	if st.Files > 0 && st.Ffree <= st.Files {
		inodePct = float64(st.Files-st.Ffree) / float64(st.Files) * 100
	}
	return max(diskPct, inodePct), true
}

// escalatedLimits returns the effective prune config for one
// shared-cache: the configured knobs unchanged under normal fs
// pressure, tightened once DiskHighPct/DiskCritPct are crossed (see
// their doc). Pressure is measured on sc itself — every pvc-* dir
// could in principle sit on a different filesystem.
func (p *Pruner) escalatedLimits(sc string, log *slog.Logger) Config {
	eff := p.cfg
	pct, ok := p.fsPressure(sc)
	if !ok || pct < eff.DiskHighPct {
		return eff
	}
	crit := pct >= eff.DiskCritPct
	ages := []*time.Duration{
		&eff.GoBuildMaxAge, &eff.ArtifactMaxAge, &eff.StaleMaxAge,
		&eff.GraphMaxAge, &eff.ToolMaxAge,
		&eff.NodeDepsDirMaxAge, &eff.NodeDepsLockAge,
	}
	for _, d := range ages {
		if crit {
			// Emergency: nearly every file in a prunable bucket is
			// stale. A small floor (not 0) keeps artifacts younger
			// than ccCritFloorAge — a lock file or staging dir being
			// written THIS minute by an in-flight install —
			// undeletable even under crit pressure.
			*d = ccCritFloorAge
		} else {
			*d /= 2 // high: prune twice as eagerly as scheduled
		}
	}
	// Size caps engage at their LOW marks — under pressure the trim
	// trigger and the trim target collapse to the low watermark.
	eff.GoBuildHighMark = eff.GoBuildLowMark
	eff.BuildHighMark = eff.BuildLowMark
	eff.NodeDepsHighMark = eff.NodeDepsLowMark
	level := "high"
	if crit {
		level = "crit"
	}
	log.Warn("fs pressure — escalating shared-cache prune",
		"usedPct", pct, "level", level)
	return eff
}

// enforcePerms is `chown 4294967294:4294967294 "$SC" "$SC"/* &&
// chmod 0777` — roots only, never recursive (see header comment).
// Failures are best-effort like the script's `&&`, but Debug-logged:
// a silently unenforced ownership invariant is how cache writes
// start landing as root.
func (p *Pruner) enforcePerms(sc string, log *slog.Logger) {
	targets := []string{sc}
	if entries, err := os.ReadDir(sc); err == nil {
		for _, e := range entries {
			p := filepath.Join(sc, e.Name())
			// Lstat each candidate — os.Chown/os.Chmod below
			// dereference symlinks onto host paths outside the
			// cache, and DirEntry.Type() is ZERO on filesystems
			// reporting DT_UNKNOWN (XFS ftype=0, overlayfs, NFS),
			// so a Type()-only guard would let a container-planted
			// `<entry> -> /etc/...` slip through as a privilege
			// gadget (concourseinit/worker_init.go parity). Only
			// real directories get the top-level perm invariant —
			// chmod 0777 on a regular file would be world-
			// writable AND executable.
			fi, err := os.Lstat(p)
			if err != nil {
				continue // raced away between ReadDir and Lstat
			}
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				continue
			}
			targets = append(targets, p)
		}
	} else {
		log.Debug("cannot list shared-cache — perms enforced on root only",
			"dir", sc, "error", err)
	}
	for _, t := range targets {
		// fd-based: open O_NOFOLLOW + Fchown/Fchmod on the held fd —
		// the Lstat above only proved no symlink AT CHECK TIME;
		// os.Chown/os.Chmod would re-resolve the path and follow a
		// swapped-in link.
		if err := enforceDirPermsFD(t, p.cfg.OwnerUID, p.cfg.OwnerGID, p.cfg.Mode); err != nil {
			log.Debug("perm invariant not enforced",
				"path", t, "error", err)
		}
	}
}
