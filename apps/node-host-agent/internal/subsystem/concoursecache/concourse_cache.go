// concourse_cache.go — native Go port of the prune.sh ConfigMap the
// concourse-workdir-janitor component used to run inside every
// concourse-worker pod via pods/exec SPDY
// (infrastructure/components/node-ops/concourse-workdir-janitor/
// script-cm.yaml — deleted by the same change).
//
// node-host-agent already runs on every node with the openebs hostdir
// mounted, so the shared-cache inside each worker PVC —
// <openebsRoot>/pvc-*/shared-cache — is pruned directly on the host:
// no pods/exec grant, no script ConfigMap, no bash inside the worker.
// The caller should schedule Sweep every
// DefaultInterval (15m — tighter than the 30m cadence
// the prune had inside the janitor run).
//
// The bucket rules are the script's 1:1 — same ages, same size caps,
// same dir-first ordering (see pruneSharedCache). Safety notes kept
// from the script:
//   - The ownership/perm invariant is enforced on shared-cache + ONE
//     level only. Files deeper in the tree are always created by uid
//     4294967294 (only unprivileged task containers see /shared-cache),
//     so a recursive chown of ~500k files is wasted I/O.
//   - NEVER touch go-mod/mise/ci-tool — they are scaffolded by
//     init-rm and cost real money to rebuild; the script deliberately
//     had no bucket for them and neither does this port.
//   - Size caps free oldest-first exactly like
//     `find -printf '%T@' | sort -n`; du -sk semantics are kept via
//     allocated blocks (st_blocks), not apparent size.
package concoursecache

import (
	"cmp"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// pvcNameRe is the last-deletion-belt name check — exactly
// pvc-<uuid>, duplicated from sweeper (the orphan-dir sweeper owns
// the same contract). Kept as a copy rather than an exported symbol
// so this package carries no sweeper dependency; the regexp is one
// line and the openebs pvc-* naming convention is stable.
var pvcNameRe = regexp.MustCompile(
	`^pvc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DefaultInterval is the cadence the caller should
// schedule — 15m vs the 30m the prune ran inside the janitor.
const DefaultInterval = 15 * time.Minute

// prune.sh constants. Size thresholds were KiB (du -sk); here bytes.
const (
	ccOwner       = 4294967294 // uid+gid unprivileged task containers run as
	ccPerm        = 0o777
	ccGoBuildHigh = 15 << 30 // 15728640 KiB
	ccGoBuildLow  = 8 << 30  //  8388608 KiB
	ccBuildHigh   = 4 << 30  //  4194304 KiB
	ccBuildLow    = 2 << 30  //  2097152 KiB
	ccNodeDepsHi  = 6 << 30  //  6291456 KiB
	ccNodeDepsLow = 4 << 30  //  4194304 KiB

	// Filesystem-pressure thresholds (used percent) for the H3 early
	// trigger — see Config.DiskHighPct/DiskCritPct.
	ccDiskHighPct = 75
	ccDiskCritPct = 85
	// ccCritFloorAge bounds the crit escalation: ages collapse to
	// this floor, not 0, so artifacts being written right now
	// (in-flight lock files / staging dirs) survive even a crit
	// prune. The cache is rebuildable — an active install isn't.
	ccCritFloorAge = 5 * time.Minute
)

// Config carries the pruner's knobs — every field maps
// to a prune.sh constant and a zero value falls back to the script
// default, so a bare Config{} IS the production config.
type Config struct {
	// Ownership/perm invariant forced on shared-cache + its first
	// level (chown 4294967294:4294967294, chmod 0777). Set both to -1
	// to skip chown entirely (unprivileged dev runs).
	OwnerUID, OwnerGID int
	Mode               os.FileMode

	GoBuildMaxAge   time.Duration // find -mtime +2
	GoBuildHighMark int64         // du > 15GiB
	GoBuildLowMark  int64         // trim oldest files to <= 8GiB

	ArtifactMaxAge time.Duration // build+coverage -mtime +1
	BuildHighMark  int64         // du > 4GiB
	BuildLowMark   int64         // oldest <key> dirs to <= 2GiB

	StaleMaxAge time.Duration // affected+ytt -mtime +2
	GraphMaxAge time.Duration // nx+moon -mtime +7
	ToolMaxAge  time.Duration // trivy/sonar/… -mtime +14

	NodeDepsDirMaxAge time.Duration // <cksum> dirs -mtime +7
	NodeDepsLockAge   time.Duration // .lock-*/.tmp-*/staging -mmin +60
	NodeDepsHighMark  int64         // du > 6GiB
	NodeDepsLowMark   int64         // oldest <cksum> dirs to <= 4GiB

	// DiskHighPct/DiskCritPct are used-percent thresholds on the
	// filesystem holding a shared-cache — the H3 early trigger. The
	// pressure reading is max(used bytes %, used inodes %): a cache
	// tree of hundreds of thousands of tiny files lands ENOSPC on
	// inode exhaustion while `df` still shows free GBs, so both
	// readings share the one trigger.
	//   >= DiskHighPct: escalate — every age limit halves and the
	//     size caps engage at their LOW marks.
	//   >= DiskCritPct: emergency — every file inside the prunable
	//     buckets is eligible (age limits collapse to 0); the buckets
	//     are all reconstructible caches while a full filesystem
	//     wedges kubelet/containerd outright.
	// A statfs failure fails open to the normal limits — the regular
	// cadence prune is the baseline, escalation is a bonus.
	DiskHighPct, DiskCritPct float64

	// statfsFn reads filesystem stats for the pressure check — seam
	// for tests; nil → syscall.Statfs.
	statfsFn func(path string, st *syscall.Statfs_t) error
	// nowFn supplies the current time — seam for tests; nil → time.Now.
	nowFn func() time.Time
}

func (c *Config) applyDefaults() {
	// -1,-1 opts out of chown; the zero value means the script's
	// 4294967294 — chown to root was never a supported mode.
	if c.OwnerUID == 0 && c.OwnerGID == 0 {
		c.OwnerUID, c.OwnerGID = ccOwner, ccOwner
	}
	if c.Mode == 0 {
		c.Mode = ccPerm
	}
	// find -mtime +N matches floor(age_days) > N, i.e. age >= (N+1)*24h
	// — one day LATER than a naive N*24h read.
	if c.GoBuildMaxAge <= 0 {
		c.GoBuildMaxAge = 72 * time.Hour // -mtime +2
	}
	if c.GoBuildHighMark <= 0 {
		c.GoBuildHighMark = ccGoBuildHigh
	}
	if c.GoBuildLowMark <= 0 {
		c.GoBuildLowMark = ccGoBuildLow
	}
	if c.ArtifactMaxAge <= 0 {
		c.ArtifactMaxAge = 48 * time.Hour // -mtime +1
	}
	if c.BuildHighMark <= 0 {
		c.BuildHighMark = ccBuildHigh
	}
	if c.BuildLowMark <= 0 {
		c.BuildLowMark = ccBuildLow
	}
	if c.StaleMaxAge <= 0 {
		c.StaleMaxAge = 72 * time.Hour // -mtime +2
	}
	if c.GraphMaxAge <= 0 {
		c.GraphMaxAge = 8 * 24 * time.Hour // -mtime +7
	}
	if c.ToolMaxAge <= 0 {
		c.ToolMaxAge = 15 * 24 * time.Hour // -mtime +14
	}
	if c.NodeDepsDirMaxAge <= 0 {
		c.NodeDepsDirMaxAge = 8 * 24 * time.Hour // -mtime +7
	}
	if c.NodeDepsLockAge <= 0 {
		c.NodeDepsLockAge = 61 * time.Minute // -mmin +60
	}
	if c.NodeDepsHighMark <= 0 {
		c.NodeDepsHighMark = ccNodeDepsHi
	}
	if c.NodeDepsLowMark <= 0 {
		c.NodeDepsLowMark = ccNodeDepsLow
	}
	if c.DiskHighPct <= 0 {
		c.DiskHighPct = ccDiskHighPct
	}
	if c.DiskCritPct <= 0 {
		c.DiskCritPct = ccDiskCritPct
	}
	if c.statfsFn == nil {
		c.statfsFn = syscall.Statfs
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
}

// Pruner prunes the Concourse shared-cache inside every
// worker PVC — <openebsRoot>/pvc-*/shared-cache — directly on the
// host, the native replacement for exec'ing prune.sh into each pod.
type Pruner struct {
	cfg Config

	cycles       *prometheus.CounterVec // result: ok|abort
	filesDeleted *prometheus.CounterVec // bucket label
	bytesFreed   prometheus.Counter
}

// New returns a pruner and registers its metrics
// on reg — same contract as the orphan sweeper's New.
func New(cfg Config, reg prometheus.Registerer) (*Pruner, error) {
	cfg.applyDefaults()
	p := &Pruner{cfg: cfg}
	p.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_concourse_cache_cycles_total",
		Help: "Concourse shared-cache prune passes by result (ok|abort).",
	}, []string{"result"})
	p.filesDeleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_concourse_cache_files_deleted_total",
		Help: "Files removed by the shared-cache pruner, per bucket.",
	}, []string{"bucket"})
	p.bytesFreed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_concourse_cache_bytes_freed_total",
		Help: "Bytes freed by the shared-cache pruner (file sizes/du).",
	})
	if reg != nil {
		for _, c := range []prometheus.Collector{p.cycles, p.filesDeleted, p.bytesFreed} {
			if err := reg.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

// SweepSharedCache runs one prune pass over
// <openebsRoot>/pvc-*/shared-cache with the script defaults — the
// convenience entry point for callers that need no metrics or custom
// thresholds.
func SweepSharedCache(ctx context.Context, openebsRoot string) error {
	p, err := New(Config{}, nil)
	if err != nil {
		return err
	}
	return p.Sweep(ctx, openebsRoot)
}

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
			filepath.Join(openebsRoot, e.Name(), "shared-cache"))
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
			// Lstat filter: skip symlinks — os.Chown/os.Chmod below
			// dereference them onto host paths outside the cache.
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			targets = append(targets, filepath.Join(sc, e.Name()))
		}
	} else {
		log.Debug("cannot list shared-cache — perms enforced on root only",
			"dir", sc, "error", err)
	}
	for _, t := range targets {
		if p.cfg.OwnerUID >= 0 || p.cfg.OwnerGID >= 0 {
			if err := os.Chown(t, p.cfg.OwnerUID, p.cfg.OwnerGID); err != nil {
				log.Debug("chown failed — perm invariant not enforced",
					"path", t, "error", err)
			}
		}
		if err := os.Chmod(t, p.cfg.Mode); err != nil {
			log.Debug("chmod failed — perm invariant not enforced",
				"path", t, "error", err)
		}
	}
}

// pruneGoBuild is the go-build bucket: files older than GoBuildMaxAge
// deleted, then oldest files trimmed until du <= GoBuildLowMark when
// the bucket exceeds GoBuildHighMark.
func (p *Pruner) pruneGoBuild(ctx context.Context, sc string, cfg Config, log *slog.Logger) {
	dir := filepath.Join(sc, "go-build")
	if !isDir(dir) {
		return
	}
	p.deleteOldFiles(ctx, dir, "go-build", cfg.GoBuildMaxAge, log)

	sz := int64(diskUsage(dir))
	if sz <= cfg.GoBuildHighMark {
		return
	}
	need := sz - cfg.GoBuildLowMark
	var acc int64
	var freed int64
	var failed int
	var lastErr error
	for _, f := range filesByAge(dir) {
		if ctx.Err() != nil || acc >= need {
			break
		}
		// Selected on apparent size (find -printf %s) exactly like
		// the awk accumulator — removal failure does not re-run.
		acc += f.size
		if err := os.Remove(f.path); err == nil {
			freed += f.size
			p.filesDeleted.WithLabelValues("go-build").Inc()
			p.bytesFreed.Add(float64(f.size))
		} else {
			failed++
			lastErr = err
		}
	}
	if failed > 0 {
		log.Warn("go-build trim removals failed",
			"files", failed, "error", lastErr)
	}
	// freed is the successful-remove total — logging it avoids a
	// second full-tree du just for the "after" number.
	log.Info("go-build trimmed",
		"beforeGiB", float64(sz)/(1<<30),
		"freedGiB", float64(freed)/(1<<30))
}

// pruneAgeBucket is `find -type f -mtime +N -delete` plus the optional
// `find -mindepth 1 -type d -empty -delete` some buckets carry.
func (p *Pruner) pruneAgeBucket(ctx context.Context, sc, bucket string, maxAge time.Duration, emptyDirs bool, log *slog.Logger) {
	dir := filepath.Join(sc, bucket)
	if !isDir(dir) {
		return
	}
	p.deleteOldFiles(ctx, dir, bucket, maxAge, log)
	if emptyDirs {
		p.deleteEmptyDirs(ctx, dir, log)
	}
}

// deleteOldFiles removes regular files under dir whose mtime is older
// than maxAge (-type f -mtime +N -delete). Errors are skipped like
// the script's `|| true`; ctx cancellation stops the walk.
func (p *Pruner) deleteOldFiles(ctx context.Context, dir, bucket string, maxAge time.Duration, log *slog.Logger) {
	now := p.cfg.nowFn()
	var n, failed int
	var bytes int64
	var lastErr error
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || now.Sub(info.ModTime()) <= maxAge {
			return nil
		}
		if err := os.Remove(path); err == nil {
			n++
			bytes += info.Size()
		} else {
			failed++
			lastErr = err
		}
		return nil
	})
	if n > 0 {
		p.filesDeleted.WithLabelValues(bucket).Add(float64(n))
		p.bytesFreed.Add(float64(bytes))
		log.Info("age prune", "bucket", bucket,
			"files", n, "freedGiB", float64(bytes)/(1<<30))
	}
	if failed > 0 {
		log.Warn("age prune removals failed",
			"bucket", bucket, "files", failed, "error", lastErr)
	}
}

// deleteEmptyDirs is `find dir -mindepth 1 -type d -empty -delete`:
// deepest dirs first (-delete implies -depth), so a chain of dirs
// that only hold empty dirs collapses to the top. dir itself is
// never removed (mindepth 1).
func (p *Pruner) deleteEmptyDirs(ctx context.Context, dir string, log *slog.Logger) {
	var dirs []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err == nil && d.IsDir() && path != dir {
			dirs = append(dirs, path)
		}
		return nil
	})
	// WalkDir visits parents before children (pre-order), so reversed
	// collection order puts every dir after ALL its descendants —
	// the same deepest-first collapse the separator-count sort gave,
	// without materializing a second ordering.
	slices.Reverse(dirs)
	var n int
	for _, d := range dirs {
		if ctx.Err() != nil {
			break
		}
		if err := os.Remove(d); err == nil {
			n++
		}
	}
	if n > 0 {
		log.Info("empty dirs pruned", "dir", dir, "dirs", n)
	}
}

// capTopLevelDirs is the `du -sk` size cap on first-level dirs: over
// high → rm -rf the oldest <key>/<cksum> dirs (sorted by mtime) until
// at least du-low has been freed. writable adds `chmod -R u+w` before
// rm (node-deps subdirs can be read-only — bun install chmod a-w).
func (p *Pruner) capTopLevelDirs(ctx context.Context, sc, bucket string, high, low int64, writable bool, log *slog.Logger) {
	dir := filepath.Join(sc, bucket)
	if !isDir(dir) {
		return
	}
	// ONE walk gives the bucket du AND every first-level dir's share
	// — the per-candidate diskUsage calls below used to re-walk each
	// <key>/<cksum> subtree on top of the bucket walk.
	sz, perDir := diskUsageByTopDir(dir)
	if int64(sz) <= high {
		return
	}
	need := int64(sz) - low
	var freed int64
	for _, d := range topLevelDirsByAge(dir) {
		if ctx.Err() != nil || freed >= need {
			break
		}
		dsz := int64(perDir[filepath.Base(d.path)])
		if writable {
			makeWritable(d.path)
		}
		if err := os.RemoveAll(d.path); err == nil {
			p.bytesFreed.Add(float64(dsz))
		} else {
			log.Warn(bucket+": rm -rf failed — cap accounting may overshoot",
				"dir", d.path, "error", err)
		}
		// freed is accumulated unconditionally — the shell did
		// `rm -rf; freed+=dsz` without checking rm's exit.
		freed += dsz
	}
	// freed is the accounted total — logging it avoids a second
	// full-tree du just for the "after" number.
	log.Info(bucket+" trimmed",
		"beforeGiB", float64(sz)/(1<<30),
		"freedGiB", float64(freed)/(1<<30))
}

// pruneNodeDeps is the node-deps bucket (<cksum> node_modules cache):
// <cksum> dirs untouched for 7d, stale .lock-*/.tmp-* files older than
// 60m, crashed *.tmp-* staging dirs older than 60m, then the 6→4GiB
// cap. Every rm -rf is preceded by chmod -R u+w (bun install makes
// trees read-only).
func (p *Pruner) pruneNodeDeps(ctx context.Context, sc string, cfg Config, log *slog.Logger) {
	dir := filepath.Join(sc, "node-deps")
	if !isDir(dir) {
		return
	}
	now := p.cfg.nowFn()

	// First-level <cksum> dirs older than the dir cap (-mtime +7 on
	// the dir itself — content mtimes do not count).
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if ctx.Err() != nil {
				break
			}
			if !e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil || now.Sub(info.ModTime()) <= cfg.NodeDepsDirMaxAge {
				continue
			}
			dpath := filepath.Join(dir, e.Name())
			makeWritable(dpath)
			if err := os.RemoveAll(dpath); err == nil {
				log.Info("node-deps: aged cksum dir removed", "dir", e.Name())
			} else {
				log.Warn("node-deps: cksum dir removal failed",
					"dir", e.Name(), "error", err)
			}
		}
	} else {
		log.Warn("node-deps: cannot list dir — aged cksum dirs not pruned",
			"dir", dir, "error", err)
	}

	// Stale .lock-*/.tmp-* FILES at any depth (-mmin +60).
	var nlocks, lockFailed int
	var lockErr error
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		if !strings.HasPrefix(name, ".lock-") && !strings.HasPrefix(name, ".tmp-") {
			return nil
		}
		info, err := d.Info()
		if err != nil || now.Sub(info.ModTime()) <= cfg.NodeDepsLockAge {
			return nil
		}
		if err := os.Remove(path); err == nil {
			nlocks++
			p.filesDeleted.WithLabelValues("node-deps").Inc()
			p.bytesFreed.Add(float64(info.Size()))
		} else {
			lockFailed++
			lockErr = err
		}
		return nil
	})
	if nlocks > 0 {
		log.Info("node-deps: stale lock/tmp files removed", "files", nlocks)
	}
	if lockFailed > 0 {
		log.Warn("node-deps: lock/tmp removals failed",
			"files", lockFailed, "error", lockErr)
	}

	// Crashed <cksum>.tmp-<nanos> staging DIRS at depth 1 (snapshot
	// save crash — a dir, never empty, so rm -rf not -delete).
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if ctx.Err() != nil {
				break
			}
			if !e.IsDir() || !strings.Contains(e.Name(), ".tmp-") {
				continue
			}
			info, err := e.Info()
			if err != nil || now.Sub(info.ModTime()) <= cfg.NodeDepsLockAge {
				continue
			}
			dpath := filepath.Join(dir, e.Name())
			makeWritable(dpath)
			if err := os.RemoveAll(dpath); err == nil {
				log.Info("node-deps: stale staging dir removed", "dir", e.Name())
			} else {
				log.Warn("node-deps: staging dir removal failed",
					"dir", e.Name(), "error", err)
			}
		}
	} else {
		log.Warn("node-deps: cannot list dir — stale staging dirs not pruned",
			"dir", dir, "error", err)
	}

	p.capTopLevelDirs(ctx, sc, "node-deps",
		cfg.NodeDepsHighMark, cfg.NodeDepsLowMark, true, log)
}

// ---------------------------------------------------------------------------
// fs helpers — du/find equivalents.
// ---------------------------------------------------------------------------

// isDir is the script's `[ -d "$d" ]` guard — but Lstat, not Stat:
// unlike the worker-container original, this pruner resolves on the
// HOST fs, so a CI task planting `<bucket> -> /etc/...` must not turn
// root chown/chmod/rm into a host-file takeover gadget.
func isDir(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.IsDir()
}

// cacheFile is one prune candidate: path + mtime + apparent size.
type cacheFile struct {
	path    string
	size    int64
	modTime time.Time
}

// entryBlocks is the du -sk contribution of one walked entry:
// allocated blocks (st_blocks×512), falling back to apparent size —
// sparse files measure like du does.
func entryBlocks(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
		return uint64(st.Blocks) * 512
	}
	return uint64(info.Size())
}

// diskUsage is du -sk×1024: allocated blocks (st_blocks×512) summed
// over the tree INCLUDING the directories themselves — never apparent
// size, so sparse files measure like du does.
func diskUsage(root string) uint64 {
	var total uint64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += entryBlocks(info)
		return nil
	})
	return total
}

// diskUsageByTopDir is diskUsage plus the per-first-level-component
// split the size caps need — one tree walk instead of a du per
// <key>/<cksum> dir. perDir is keyed by the component NAME under
// root (dirs AND loose files count; the caps only look up dirs).
func diskUsageByTopDir(root string) (total uint64, perDir map[string]uint64) {
	perDir = map[string]uint64{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		sz := entryBlocks(info)
		total += sz
		if rel, rerr := filepath.Rel(root, path); rerr == nil && rel != "." {
			if i := strings.IndexByte(rel, os.PathSeparator); i >= 0 {
				rel = rel[:i]
			}
			perDir[rel] += sz
		}
		return nil
	})
	return total, perDir
}

// filesByAge lists every regular file under root sorted oldest-first —
// `find -type f -printf '%T@ %s %p\n' | sort -n`.
func filesByAge(root string) []cacheFile {
	var out []cacheFile
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			out = append(out, cacheFile{path: path, size: info.Size(), modTime: info.ModTime()})
		}
		return nil
	})
	slices.SortFunc(out, func(a, b cacheFile) int {
		return cmp.Compare(a.modTime.UnixNano(), b.modTime.UnixNano())
	})
	return out
}

// topLevelDirsByAge lists first-level dirs sorted oldest-first —
// `find -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n`.
func topLevelDirsByAge(root string) []cacheFile {
	var out []cacheFile
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if info, err := e.Info(); err == nil {
				out = append(out, cacheFile{
					path:    filepath.Join(root, e.Name()),
					modTime: info.ModTime(),
				})
			}
		}
	}
	slices.SortFunc(out, func(a, b cacheFile) int {
		return cmp.Compare(a.modTime.UnixNano(), b.modTime.UnixNano())
	})
	return out
}

// makeWritable is `chmod -R u+w` — node-deps subdirs can be read-only
// (bun install chmod a-w), which would defeat rm -rf.
func makeWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip symlinks: coreutils chmod -R never touches link targets
		// (node_modules .bin is a symlink farm onto other trees).
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if info, err := d.Info(); err == nil {
			_ = os.Chmod(path, info.Mode().Perm()|0o200)
		}
		return nil
	})
}
