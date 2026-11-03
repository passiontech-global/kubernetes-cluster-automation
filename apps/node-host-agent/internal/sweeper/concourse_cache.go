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
// DefaultConcourseCacheInterval (15m — tighter than the 30m cadence
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
package sweeper

import (
	"cmp"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// DefaultConcourseCacheInterval is the cadence the caller should
// schedule — 15m vs the 30m the prune ran inside the janitor.
const DefaultConcourseCacheInterval = 15 * time.Minute

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
)

// ConcourseCacheConfig carries the pruner's knobs — every field maps
// to a prune.sh constant and a zero value falls back to the script
// default, so a bare ConcourseCacheConfig{} IS the production config.
type ConcourseCacheConfig struct {
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

	// nowFn supplies the current time — seam for tests; nil → time.Now.
	nowFn func() time.Time
}

func (c *ConcourseCacheConfig) applyDefaults() {
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
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
}

// ConcourseCachePruner prunes the Concourse shared-cache inside every
// worker PVC — <openebsRoot>/pvc-*/shared-cache — directly on the
// host, the native replacement for exec'ing prune.sh into each pod.
type ConcourseCachePruner struct {
	cfg ConcourseCacheConfig

	cycles       *prometheus.CounterVec // result: ok|abort
	filesDeleted *prometheus.CounterVec // bucket label
	bytesFreed   prometheus.Counter
}

// NewConcourseCachePruner returns a pruner and registers its metrics
// on reg — same contract as sweeper.New.
func NewConcourseCachePruner(cfg ConcourseCacheConfig, reg prometheus.Registerer) (*ConcourseCachePruner, error) {
	cfg.applyDefaults()
	p := &ConcourseCachePruner{cfg: cfg}
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

// SweepConcourseSharedCache runs one prune pass over
// <openebsRoot>/pvc-*/shared-cache with the script defaults — the
// convenience entry point for callers that need no metrics or custom
// thresholds.
func SweepConcourseSharedCache(ctx context.Context, openebsRoot string) error {
	p, err := NewConcourseCachePruner(ConcourseCacheConfig{}, nil)
	if err != nil {
		return err
	}
	return p.Sweep(ctx, openebsRoot)
}

// Sweep runs one prune pass over every pvc-*/shared-cache under
// openebsRoot. The glob is the same pvc-* prefix the orphan sweeper
// uses; non-pvc dirs and pvc dirs without a shared-cache are skipped
// (the script's `[ -d "$SC" ] || exit 0`).
func (p *ConcourseCachePruner) Sweep(ctx context.Context, openebsRoot string) error {
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
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "pvc-") {
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
func (p *ConcourseCachePruner) pruneSharedCache(ctx context.Context, sc string) {
	log := slog.With("subsystem", "concourse-cache", "dir", sc)
	if !isDir(sc) {
		return // init-rm not done yet — nothing to prune
	}
	p.enforcePerms(sc)

	// go-build: stale entries + its own size cap.
	p.pruneGoBuild(ctx, sc, log)

	// Artifact bus: 24h files + empty dirs, then the build <key> cap.
	for _, b := range []string{"build", "coverage"} {
		p.pruneAgeBucket(ctx, sc, b, p.cfg.ArtifactMaxAge, true, log)
	}
	p.capTopLevelDirs(ctx, sc, "build",
		p.cfg.BuildHighMark, p.cfg.BuildLowMark, false, log)

	// affected + ytt: 48h files, no dir cleanup.
	for _, b := range []string{"affected", "ytt"} {
		p.pruneAgeBucket(ctx, sc, b, p.cfg.StaleMaxAge, false, log)
	}
	// nx + moon task-graph caches: 7d files + empty dirs.
	for _, b := range []string{"nx", "moon"} {
		p.pruneAgeBucket(ctx, sc, b, p.cfg.GraphMaxAge, true, log)
	}
	// Scanner/tool caches: 14d files + empty dirs.
	for _, b := range []string{"trivy", "sonar", "golangci-lint",
		"uv", "pip", "bin", "py-tools", "bun"} {
		p.pruneAgeBucket(ctx, sc, b, p.cfg.ToolMaxAge, true, log)
	}
	p.pruneNodeDeps(ctx, sc, log)
}

// enforcePerms is `chown 4294967294:4294967294 "$SC" "$SC"/* &&
// chmod 0777` — roots only, never recursive (see header comment).
func (p *ConcourseCachePruner) enforcePerms(sc string) {
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
	}
	for _, t := range targets {
		if p.cfg.OwnerUID >= 0 || p.cfg.OwnerGID >= 0 {
			_ = os.Chown(t, p.cfg.OwnerUID, p.cfg.OwnerGID)
		}
		_ = os.Chmod(t, p.cfg.Mode)
	}
}

// pruneGoBuild is the go-build bucket: files older than GoBuildMaxAge
// deleted, then oldest files trimmed until du <= GoBuildLowMark when
// the bucket exceeds GoBuildHighMark.
func (p *ConcourseCachePruner) pruneGoBuild(ctx context.Context, sc string, log *slog.Logger) {
	dir := filepath.Join(sc, "go-build")
	if !isDir(dir) {
		return
	}
	p.deleteOldFiles(ctx, dir, "go-build", p.cfg.GoBuildMaxAge, log)

	sz := int64(diskUsage(dir))
	if sz <= p.cfg.GoBuildHighMark {
		return
	}
	need := sz - p.cfg.GoBuildLowMark
	var acc int64
	for _, f := range filesByAge(dir) {
		if ctx.Err() != nil || acc >= need {
			break
		}
		// Selected on apparent size (find -printf %s) exactly like
		// the awk accumulator — removal failure does not re-run.
		acc += f.size
		if err := os.Remove(f.path); err == nil {
			p.filesDeleted.WithLabelValues("go-build").Inc()
			p.bytesFreed.Add(float64(f.size))
		}
	}
	log.Info("go-build trimmed",
		"beforeGiB", float64(sz)/(1<<30),
		"afterGiB", float64(diskUsage(dir))/(1<<30))
}

// pruneAgeBucket is `find -type f -mtime +N -delete` plus the optional
// `find -mindepth 1 -type d -empty -delete` some buckets carry.
func (p *ConcourseCachePruner) pruneAgeBucket(ctx context.Context, sc, bucket string, maxAge time.Duration, emptyDirs bool, log *slog.Logger) {
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
func (p *ConcourseCachePruner) deleteOldFiles(ctx context.Context, dir, bucket string, maxAge time.Duration, log *slog.Logger) {
	now := p.cfg.nowFn()
	var n int
	var bytes int64
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
		}
		return nil
	})
	if n > 0 {
		p.filesDeleted.WithLabelValues(bucket).Add(float64(n))
		p.bytesFreed.Add(float64(bytes))
		log.Info("age prune", "bucket", bucket,
			"files", n, "freedGiB", float64(bytes)/(1<<30))
	}
}

// deleteEmptyDirs is `find dir -mindepth 1 -type d -empty -delete`:
// deepest dirs first (-delete implies -depth), so a chain of dirs
// that only hold empty dirs collapses to the top. dir itself is
// never removed (mindepth 1).
func (p *ConcourseCachePruner) deleteEmptyDirs(ctx context.Context, dir string, log *slog.Logger) {
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
	slices.SortFunc(dirs, func(a, b string) int {
		return strings.Count(b, string(os.PathSeparator)) -
			strings.Count(a, string(os.PathSeparator))
	})
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
func (p *ConcourseCachePruner) capTopLevelDirs(ctx context.Context, sc, bucket string, high, low int64, writable bool, log *slog.Logger) {
	dir := filepath.Join(sc, bucket)
	if !isDir(dir) {
		return
	}
	sz := int64(diskUsage(dir))
	if sz <= high {
		return
	}
	need := sz - low
	var freed int64
	for _, d := range topLevelDirsByAge(dir) {
		if ctx.Err() != nil || freed >= need {
			break
		}
		dsz := int64(diskUsage(d.path))
		if writable {
			makeWritable(d.path)
		}
		if err := os.RemoveAll(d.path); err == nil {
			p.bytesFreed.Add(float64(dsz))
		}
		// freed is accumulated unconditionally — the shell did
		// `rm -rf; freed+=dsz` without checking rm's exit.
		freed += dsz
	}
	log.Info(bucket+" trimmed",
		"beforeGiB", float64(sz)/(1<<30),
		"afterGiB", float64(diskUsage(dir))/(1<<30))
}

// pruneNodeDeps is the node-deps bucket (<cksum> node_modules cache):
// <cksum> dirs untouched for 7d, stale .lock-*/.tmp-* files older than
// 60m, crashed *.tmp-* staging dirs older than 60m, then the 6→4GiB
// cap. Every rm -rf is preceded by chmod -R u+w (bun install makes
// trees read-only).
func (p *ConcourseCachePruner) pruneNodeDeps(ctx context.Context, sc string, log *slog.Logger) {
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
			if err != nil || now.Sub(info.ModTime()) <= p.cfg.NodeDepsDirMaxAge {
				continue
			}
			dpath := filepath.Join(dir, e.Name())
			makeWritable(dpath)
			if err := os.RemoveAll(dpath); err == nil {
				log.Info("node-deps: aged cksum dir removed", "dir", e.Name())
			}
		}
	}

	// Stale .lock-*/.tmp-* FILES at any depth (-mmin +60).
	var nlocks int
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
		if err != nil || now.Sub(info.ModTime()) <= p.cfg.NodeDepsLockAge {
			return nil
		}
		if err := os.Remove(path); err == nil {
			nlocks++
			p.filesDeleted.WithLabelValues("node-deps").Inc()
			p.bytesFreed.Add(float64(info.Size()))
		}
		return nil
	})
	if nlocks > 0 {
		log.Info("node-deps: stale lock/tmp files removed", "files", nlocks)
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
			if err != nil || now.Sub(info.ModTime()) <= p.cfg.NodeDepsLockAge {
				continue
			}
			dpath := filepath.Join(dir, e.Name())
			makeWritable(dpath)
			if err := os.RemoveAll(dpath); err == nil {
				log.Info("node-deps: stale staging dir removed", "dir", e.Name())
			}
		}
	}

	p.capTopLevelDirs(ctx, sc, "node-deps",
		p.cfg.NodeDepsHighMark, p.cfg.NodeDepsLowMark, true, log)
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
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
			total += uint64(st.Blocks) * 512
		} else {
			total += uint64(info.Size())
		}
		return nil
	})
	return total
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
