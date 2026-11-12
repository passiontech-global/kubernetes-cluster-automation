// prune.go — the bucket mechanics: go-build trim, generic age buckets
// (-mtime +N -delete / empty-dir collapse), the du-style top-level
// size caps and the node-deps cksum/lock/staging-dir rules.
package concoursecache

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

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
		// Selected on allocated blocks (entryBlocks) in the same du-style
		// units as the high/low marks and the `sz` above — removal
		// failure does not re-run.
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
	now := p.cfg.Clock.Now()
	var n, failed int
	var bytes int64
	var lastErr error
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			log.Debug("age prune: unreadable entry skipped",
				"bucket", bucket, "path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Debug("age prune: unreadable entry skipped",
				"bucket", bucket, "path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if now.Sub(info.ModTime()) <= maxAge {
			return nil
		}
		if err := os.Remove(path); err == nil {
			n++
			// st.Blocks*512, not Size(): the freed-bytes gauge is
			// "what the disk actually got back" — a sparse or
			// tail-packed file's logical Size() can wildly exceed
			// (sparse) or fall short of (block tail padding) its
			// footprint. The type assertion is checked — a
			// non-*Stat_t FileInfo (non-Linux dev box, exotic fs)
			// falls back to logical Size() instead of panicking
			// mid-sweep.
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				bytes += st.Blocks * 512
			} else {
				bytes += info.Size()
			}
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
		err := os.RemoveAll(d.path)
		if writable && err != nil {
			err = removeTree(d.path)
		}
		if err == nil {
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
	now := p.cfg.Clock.Now()

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
			if err := removeTree(dpath); err == nil {
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
		if err != nil {
			log.Debug("node-deps: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		if !strings.HasPrefix(name, ".lock-") && !strings.HasPrefix(name, ".tmp-") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Debug("node-deps: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if now.Sub(info.ModTime()) <= cfg.NodeDepsLockAge {
			return nil
		}
		if err := os.Remove(path); err == nil {
			nlocks++
			p.filesDeleted.WithLabelValues("node-deps").Inc()
			// st.Blocks×512, not Size(): bytesFreed is "what the disk
			// actually got back" — the same du-style units the caps
			// and every other bytesFreed site report (a sparse or
			// tail-packed lock file's Size() can wildly exceed or
			// fall short of its footprint).
			p.bytesFreed.Add(float64(entryBlocks(info)))
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
			if err := removeTree(dpath); err == nil {
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
