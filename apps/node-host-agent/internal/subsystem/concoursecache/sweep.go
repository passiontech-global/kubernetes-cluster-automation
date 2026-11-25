// sweep.go — the sweep orchestration: the pvc-*/shared-cache walk,
// the per-cache prune order, fs-pressure escalation (statfs →
// high/crit tightened limits) and the one-level ownership/perm
// invariant enforced before pruning, all pinned via *os.Root.
package concoursecache

import (
	"context"
	"io/fs"
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
// Non-matching dirs, symlinked pvc/shared-cache dirs, and pvc dirs
// without a shared-cache are skipped (the script's `[ -d "$SC" ] || exit 0`).
func (p *Pruner) Sweep(ctx context.Context, openebsRoot string) error {
	root, err := openDirRootNoSymlink(openebsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			p.cycles.WithLabelValues("ok").Inc()
			return nil
		}
		p.cycles.WithLabelValues("abort").Inc()
		return err
	}
	defer func() { _ = root.Close() }()

	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		p.cycles.WithLabelValues("abort").Inc()
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			p.cycles.WithLabelValues("abort").Inc()
			return err
		}
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 || !pvcNameRe.MatchString(e.Name()) {
			continue
		}
		pvcRoot, err := openSubRootNoSymlink(root, e.Name())
		if err != nil {
			continue
		}
		scRoot, err := openSubRootNoSymlink(pvcRoot, concourse.SharedCacheName)
		_ = pvcRoot.Close()
		if err != nil {
			continue
		}
		p.pruneSharedCacheRoot(ctx, scRoot,
			filepath.Join(openebsRoot, e.Name(), concourse.SharedCacheName))
		_ = scRoot.Close()
	}
	p.cycles.WithLabelValues("ok").Inc()
	return nil
}

func (p *Pruner) pruneSharedCacheRoot(ctx context.Context, scRoot *os.Root, scDisplay string) {
	log := logger().With("subsystem", "concourse-cache", "cacheRoot", scDisplay)
	p.enforcePermsRoot(scRoot, log)
	eff := p.escalatedLimits(scDisplay, log)

	// go-build: stale entries + its own size cap.
	p.pruneGoBuildRoot(ctx, scRoot, eff, log)

	// Artifact bus: 24h files + empty dirs, then the build <key> cap.
	for _, b := range []string{"build", "coverage"} {
		p.pruneAgeBucketRoot(ctx, scRoot, b, eff.ArtifactMaxAge, true, log)
	}
	p.capTopLevelDirsRoot(ctx, scRoot, "build",
		eff.BuildHighMark, eff.BuildLowMark, false, log)

	// affected + ytt + pr: 48h files, no dir cleanup. pr is the
	// PR-build partition root (<shared>/pr/<tool>) — its nested
	// tool dirs are recreated by CI, so only stale files age out.
	for _, b := range []string{"affected", "ytt", "pr"} {
		p.pruneAgeBucketRoot(ctx, scRoot, b, eff.StaleMaxAge, false, log)
	}
	// nx + moon task-graph caches: 7d files + empty dirs.
	for _, b := range []string{"nx", "moon"} {
		p.pruneAgeBucketRoot(ctx, scRoot, b, eff.GraphMaxAge, true, log)
	}
	// Scanner/tool caches: 14d files + empty dirs.
	for _, b := range []string{"trivy", "sonar", "golangci-lint",
		"uv", "pip", "bin", "py-tools", "bun", "proto", "uv-tools"} {
		p.pruneAgeBucketRoot(ctx, scRoot, b, eff.ToolMaxAge, true, log)
	}
	p.pruneNodeDepsRoot(ctx, scRoot, eff, log)
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
		"usedPct", pct, "pressureLevel", level)
	return eff
}

// enforcePerms is `chown 4294967294:4294967294 "$SC" "$SC"/* &&
// chmod 0777` — roots only, never recursive (see header comment).
// Failures are best-effort like the script's `&&`, but Debug-logged:
// a silently unenforced ownership invariant is how cache writes
// start landing as root.
func (p *Pruner) enforcePerms(sc string, log *slog.Logger) {
	scRoot, err := openDirRootNoSymlink(sc)
	if err != nil {
		log.Debug("cannot open shared-cache root — perms not enforced",
			"cacheRoot", sc, "error", err)
		return
	}
	defer func() { _ = scRoot.Close() }()
	p.enforcePermsRoot(scRoot, log.With("cacheRoot", sc))
}

func (p *Pruner) enforcePermsRoot(scRoot *os.Root, log *slog.Logger) {
	targets := []string{"."}
	if entries, err := fs.ReadDir(scRoot.FS(), "."); err == nil {
		for _, e := range entries {
			name := e.Name()
			// Lstat each candidate relative to scRoot — only real
			// directories get the top-level perm invariant.
			fi, err := scRoot.Lstat(name)
			if err != nil {
				continue // raced away between ReadDir and Lstat
			}
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				continue
			}
			targets = append(targets, name)
		}
	} else {
		log.Debug("cannot list shared-cache — perms enforced on root only",
			"error", err)
	}
	for _, t := range targets {
		// fd-based: open O_NOFOLLOW relative to scRoot + Fchown/Fchmod
		// on the held fd — blocks both escaping and intra-root symlinks.
		if err := enforceDirPermsRootFD(scRoot, t, p.cfg.OwnerUID, p.cfg.OwnerGID, p.cfg.Mode); err != nil {
			log.Debug("perm invariant not enforced",
				"path", t, "error", err)
		}
	}
}
