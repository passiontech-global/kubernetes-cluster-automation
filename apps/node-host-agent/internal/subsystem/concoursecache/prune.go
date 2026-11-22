// prune.go — the bucket mechanics: go-build trim, generic age buckets
// (-mtime +N -delete / empty-dir collapse), the du-style top-level
// size caps and the node-deps cksum/lock/staging-dir rules. All fs
// operations run relative to *os.Root handles pinned against symlinks.
package concoursecache

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/concourse"
)

// goBuildIndexLen is the exact record size of a Go build-cache index
// ("-a") entry — cmd/go/internal/cache writes
// "v1 <64-hex actionID> <64-hex outputID> <20-wide size> <20-wide mtime>\n"
// (entrySize = 175). Anything else is a miss to the go command too.
const goBuildIndexLen = 175

// pruneGoBuild bounds every Go build cache under shared-cache: the
// shared "go-build" bucket plus per-job siblings ("go-build-<tag>" —
// ci-tool points phase-isolated GOCACHEs at siblings like
// "go-build-lint-<job>", same layout, same hazards, previously never
// pruned). Each dir gets the same age+size-cap pass.
func (p *Pruner) pruneGoBuild(ctx context.Context, sc string, cfg Config, log *slog.Logger) {
	scRoot, err := openDirRootNoSymlink(sc)
	if err != nil {
		return
	}
	defer func() { _ = scRoot.Close() }()
	p.pruneGoBuildRoot(ctx, scRoot, cfg, log)
}

func (p *Pruner) pruneGoBuildRoot(ctx context.Context, scRoot *os.Root, cfg Config, log *slog.Logger) {
	entries, err := fs.ReadDir(scRoot.FS(), ".")
	if err != nil {
		return
	}
	for _, e := range entries {
		if cerr := ctx.Err(); cerr != nil {
			return
		}
		name := e.Name()
		if name != "go-build" && !strings.HasPrefix(name, "go-build-") {
			continue
		}
		// DirEntry.IsDir is type-bit only — verify via openSubRootNoSymlink
		// so neither an escaping nor an intra-root symlink is followed.
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		dirRoot, err := openSubRootNoSymlink(scRoot, name)
		if err != nil {
			continue
		}
		p.pruneGoBuildDirRoot(ctx, dirRoot, name, cfg, log)
		_ = dirRoot.Close()
	}
}

// goBuildEntryKind classifies a cache file by suffix: "-a" action
// index entries and "-d" output files are the only records whose
// deletion can corrupt a live lookup; everything else (trim.txt,
// README, strays) prunes like an ordinary file.
func goBuildEntryKind(name string) byte {
	if strings.HasSuffix(name, "-a") {
		return 'a'
	}
	if strings.HasSuffix(name, "-d") {
		return 'd'
	}
	return 0
}

// goBuildReferencedOutputRoot parses a "-a" index record opened with
// O_RDONLY|O_NOFOLLOW|O_NONBLOCK + Fstat S_IFREG check inside dirRoot,
// and returns the root-relative "-d" output path it references.
// ok=false for symlinks, FIFOs, directories, or malformed records.
func goBuildReferencedOutputRoot(dirRoot *os.Root, indexRel string) (string, bool) {
	var buf [goBuildIndexLen + 1]byte
	n := 0
	err := concourse.WithNoFollowRootFD(dirRoot, indexRel, true, func(fd int, st *unix.Stat_t) error {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%s: not a regular file", indexRel)
		}
		for n < len(buf) {
			r, rerr := unix.Read(fd, buf[n:])
			if r > 0 {
				n += r
				continue
			}
			if rerr == unix.EINTR {
				continue
			}
			if rerr != nil {
				return rerr
			}
			break
		}
		return nil
	})
	if err != nil || n != goBuildIndexLen {
		return "", false
	}
	rec := buf[:goBuildIndexLen]
	if rec[0] != 'v' || rec[1] != '1' || rec[2] != ' ' ||
		rec[67] != ' ' || rec[132] != ' ' || rec[153] != ' ' ||
		rec[174] != '\n' {
		return "", false
	}
	oid := rec[68:132]
	for _, c := range oid {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return path.Join(string(oid[0:2]), string(oid)+"-d"), true
}

// pruneGoBuildDirRoot runs one pass over a single Go build cache dir:
// files older than GoBuildMaxAge are deleted while surviving entries
// accumulate block disk usage (including directories) and size-trim
// candidates; then if total usage exceeds GoBuildHighMark, oldest
// files are trimmed until <= GoBuildLowMark.
func (p *Pruner) pruneGoBuildDirRoot(ctx context.Context, dirRoot *os.Root, bucket string, cfg Config, log *slog.Logger) {
	now := p.cfg.Clock.Now()
	var ageDeleted, ageFailed int
	var ageFreed int64
	var ageErr error
	var sz uint64
	var graceBytes int64
	var candidates []cacheFile
	var dataFiles []cacheFile // "-d" outputs — deferred until index refs are known
	var indexFiles []string   // "-a" indexes that survived the age prune

	_ = fs.WalkDir(dirRoot.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			log.Debug("go-build prune: unreadable entry skipped",
				"path", rel, "error", err)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Debug("go-build prune: unreadable entry skipped",
				"path", rel, "error", err)
			return nil
		}
		blocks := entryBlocks(info)
		if !d.IsDir() && d.Type().IsRegular() {
			if now.Sub(info.ModTime()) < ccGoBuildGraceAge {
				graceBytes += int64(blocks)
				sz += blocks
				return nil
			}
			cf := cacheFile{path: rel, size: int64(blocks), modTime: info.ModTime()}
			switch goBuildEntryKind(d.Name()) {
			case 'a':
				// Index entries prune like any other file — but only
				// survivors may shield their "-d" outputs this pass.
				if now.Sub(info.ModTime()) > cfg.GoBuildMaxAge {
					if rerr := unlinkRootNoFollow(dirRoot, rel, 0); rerr == nil {
						ageDeleted++
						ageFreed += int64(blocks)
						return nil
					} else {
						ageFailed++
						ageErr = rerr
					}
				}
				indexFiles = append(indexFiles, rel)
				candidates = append(candidates, cf)
			case 'd':
				// Defer: protection depends on surviving index
				// entries, known only after the walk + parse.
				dataFiles = append(dataFiles, cf)
			default:
				if now.Sub(info.ModTime()) > cfg.GoBuildMaxAge {
					if rerr := unlinkRootNoFollow(dirRoot, rel, 0); rerr == nil {
						ageDeleted++
						ageFreed += int64(blocks)
						return nil
					} else {
						ageFailed++
						ageErr = rerr
					}
				}
				candidates = append(candidates, cf)
			}
		}
		sz += blocks
		return nil
	})

	// Parse surviving index entries -> the set of "-d" outputs still
	// referenced. Only "-a" files that survived the inline age prune
	// protect: a doomed index is already gone, so its outputs are
	// orphans this same pass.
	protected := make(map[string]struct{}, len(indexFiles))
	for _, ip := range indexFiles {
		if cerr := ctx.Err(); cerr != nil {
			return
		}
		if dpath, ok := goBuildReferencedOutputRoot(dirRoot, ip); ok {
			protected[dpath] = struct{}{}
		}
	}

	var protectedBytes int64
	for _, df := range dataFiles {
		if cerr := ctx.Err(); cerr != nil {
			return
		}
		if _, ok := protected[df.path]; ok {
			protectedBytes += df.size
			continue
		}
		if now.Sub(df.modTime) > cfg.GoBuildMaxAge {
			if rerr := unlinkRootNoFollow(dirRoot, df.path, 0); rerr == nil {
				ageDeleted++
				ageFreed += df.size
			} else {
				ageFailed++
				ageErr = rerr
			}
			continue
		}
		candidates = append(candidates, df)
	}

	if ageDeleted > 0 {
		p.filesDeleted.WithLabelValues(bucket).Add(float64(ageDeleted))
		p.bytesFreed.Add(float64(ageFreed))
		log.Info("age prune", "bucket", bucket,
			"files", ageDeleted, "freedGiB", float64(ageFreed)/(1<<30))
	}
	if ageFailed > 0 {
		log.Warn("age prune removals failed",
			"bucket", bucket, "files", ageFailed, "error", ageErr)
	}
	if ctx.Err() != nil || int64(sz) <= cfg.GoBuildHighMark {
		return
	}
	slices.SortFunc(candidates, func(a, b cacheFile) int {
		return cmp.Compare(a.modTime.UnixNano(), b.modTime.UnixNano())
	})
	need := int64(sz) - cfg.GoBuildLowMark
	var acc int64
	var freed int64
	var failed int
	var lastErr error
	for _, f := range candidates {
		if ctx.Err() != nil || acc >= need {
			break
		}
		// Selected on allocated blocks (entryBlocks) in the same du-style
		// units as the high/low marks and the `sz` above — removal
		// failure does not re-run.
		acc += f.size
		if err := unlinkRootNoFollow(dirRoot, f.path, 0); err == nil {
			freed += f.size
			p.filesDeleted.WithLabelValues(bucket).Inc()
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
	if acc < need && protectedBytes+graceBytes > 0 {
		log.Warn("go-build size cap unsatisfiable — referenced outputs and in-flight entries retained",
			"bucket", bucket,
			"protectedGiB", float64(protectedBytes)/(1<<30),
			"graceGiB", float64(graceBytes)/(1<<30))
	}
	// freed is the successful-remove total — logging it avoids a
	// second full-tree du just for the "after" number.
	log.Info("go-build trimmed",
		"bucket", bucket,
		"beforeGiB", float64(sz)/(1<<30),
		"freedGiB", float64(freed)/(1<<30))
}

// pruneAgeBucketRoot is `find -type f -mtime +N -delete` plus the optional
// `find -mindepth 1 -type d -empty -delete` some buckets carry.
func (p *Pruner) pruneAgeBucketRoot(ctx context.Context, scRoot *os.Root, bucket string, maxAge time.Duration, emptyDirs bool, log *slog.Logger) {
	dirRoot, err := openSubRootNoSymlink(scRoot, bucket)
	if err != nil {
		return
	}
	defer func() { _ = dirRoot.Close() }()
	p.deleteOldFilesRoot(ctx, dirRoot, bucket, maxAge, log)
	if emptyDirs {
		p.deleteEmptyDirsRoot(ctx, dirRoot, bucket, log)
	}
}

// deleteOldFiles removes regular files under dir whose mtime is older
// than maxAge (-type f -mtime +N -delete). Errors are skipped like
// the script's `|| true`; ctx cancellation stops the walk.
func (p *Pruner) deleteOldFiles(ctx context.Context, dir, bucket string, maxAge time.Duration, log *slog.Logger) {
	dirRoot, err := openDirRootNoSymlink(dir)
	if err != nil {
		return
	}
	defer func() { _ = dirRoot.Close() }()
	p.deleteOldFilesRoot(ctx, dirRoot, bucket, maxAge, log)
}

func (p *Pruner) deleteOldFilesRoot(ctx context.Context, dirRoot *os.Root, bucket string, maxAge time.Duration, log *slog.Logger) {
	now := p.cfg.Clock.Now()
	var n, failed int
	var bytes int64
	var lastErr error
	_ = fs.WalkDir(dirRoot.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			log.Debug("age prune: unreadable entry skipped",
				"bucket", bucket, "path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Debug("age prune: unreadable entry skipped",
				"bucket", bucket, "path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if now.Sub(info.ModTime()) <= maxAge {
			return nil
		}
		if err := unlinkRootNoFollow(dirRoot, rel, 0); err == nil {
			n++
			bytes += int64(entryBlocks(info))
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
	dirRoot, err := openDirRootNoSymlink(dir)
	if err != nil {
		return
	}
	defer func() { _ = dirRoot.Close() }()
	p.deleteEmptyDirsRoot(ctx, dirRoot, dir, log)
}

func (p *Pruner) deleteEmptyDirsRoot(ctx context.Context, dirRoot *os.Root, dirLabel string, log *slog.Logger) {
	var dirs []string
	_ = fs.WalkDir(dirRoot.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err == nil && d.IsDir() && d.Type()&fs.ModeSymlink == 0 && rel != "." {
			dirs = append(dirs, rel)
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
		if err := unlinkRootNoFollow(dirRoot, d, unix.AT_REMOVEDIR); err == nil {
			n++
		}
	}
	if n > 0 {
		log.Info("empty dirs pruned", "dir", dirLabel, "dirs", n)
	}
}

// capTopLevelDirs is the `du -sk` size cap on first-level dirs: over
// high → rm -rf the oldest <key>/<cksum> dirs (sorted by mtime) until
// at least du-low has been freed. writable adds `chmod -R u+w` before
// rm (node-deps subdirs can be read-only — bun install chmod a-w).
func (p *Pruner) capTopLevelDirs(ctx context.Context, sc, bucket string, high, low int64, writable bool, log *slog.Logger) {
	scRoot, err := openDirRootNoSymlink(sc)
	if err != nil {
		return
	}
	defer func() { _ = scRoot.Close() }()
	p.capTopLevelDirsRoot(ctx, scRoot, bucket, high, low, writable, log)
}

func (p *Pruner) capTopLevelDirsRoot(ctx context.Context, scRoot *os.Root, bucket string, high, low int64, writable bool, log *slog.Logger) {
	dirRoot, err := openSubRootNoSymlink(scRoot, bucket)
	if err != nil {
		return
	}
	defer func() { _ = dirRoot.Close() }()
	// ONE walk gives the bucket du AND every first-level dir's share
	// — the per-candidate diskUsage calls below used to re-walk each
	// <key>/<cksum> subtree on top of the bucket walk.
	sz, perDir := diskUsageByTopDirRoot(ctx, dirRoot)
	if ctx.Err() != nil || int64(sz) <= high {
		return
	}
	need := int64(sz) - low
	var freed int64
	for _, d := range topLevelDirsByAgeRoot(dirRoot) {
		if ctx.Err() != nil || freed >= need {
			break
		}
		dsz := int64(perDir[d.path])
		err := dirRoot.RemoveAll(d.path)
		if writable && err != nil {
			err = removeTreeRoot(dirRoot, d.path)
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
	scRoot, err := openDirRootNoSymlink(sc)
	if err != nil {
		return
	}
	defer func() { _ = scRoot.Close() }()
	p.pruneNodeDepsRoot(ctx, scRoot, cfg, log)
}

func (p *Pruner) pruneNodeDepsRoot(ctx context.Context, scRoot *os.Root, cfg Config, log *slog.Logger) {
	dirRoot, err := openSubRootNoSymlink(scRoot, "node-deps")
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("node-deps: cannot list dir — skipped",
				"dir", filepath.Join(scRoot.Name(), "node-deps"), "error", err)
		}
		return
	}
	defer func() { _ = dirRoot.Close() }()
	now := p.cfg.Clock.Now()

	// First-level <cksum> dirs older than the dir cap (-mtime +7 on
	// the dir itself — content mtimes do not count).
	if entries, err := fs.ReadDir(dirRoot.FS(), "."); err == nil {
		for _, e := range entries {
			if ctx.Err() != nil {
				break
			}
			if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
				continue
			}
			info, err := e.Info()
			if err != nil || now.Sub(info.ModTime()) <= cfg.NodeDepsDirMaxAge {
				continue
			}
			if err := removeTreeRoot(dirRoot, e.Name()); err == nil {
				log.Info("node-deps: aged cksum dir removed", "dir", e.Name())
			} else {
				log.Warn("node-deps: cksum dir removal failed",
					"dir", e.Name(), "error", err)
			}
		}
	} else {
		log.Warn("node-deps: cannot list dir — aged cksum dirs not pruned",
			"dir", "node-deps", "error", err)
	}

	// Stale .lock-*/.tmp-* FILES at any depth (-mmin +60).
	var nlocks, lockFailed int
	var lockErr error
	_ = fs.WalkDir(dirRoot.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			log.Debug("node-deps: unreadable entry skipped",
				"path", rel, "error", err)
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
				"path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if now.Sub(info.ModTime()) <= cfg.NodeDepsLockAge {
			return nil
		}
		if err := unlinkRootNoFollow(dirRoot, rel, 0); err == nil {
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
	if entries, err := fs.ReadDir(dirRoot.FS(), "."); err == nil {
		for _, e := range entries {
			if ctx.Err() != nil {
				break
			}
			if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 || !strings.Contains(e.Name(), ".tmp-") {
				continue
			}
			info, err := e.Info()
			if err != nil || now.Sub(info.ModTime()) <= cfg.NodeDepsLockAge {
				continue
			}
			if err := removeTreeRoot(dirRoot, e.Name()); err == nil {
				log.Info("node-deps: stale staging dir removed", "dir", e.Name())
			} else {
				log.Warn("node-deps: staging dir removal failed",
					"dir", e.Name(), "error", err)
			}
		}
	} else {
		log.Warn("node-deps: cannot list dir — stale staging dirs not pruned",
			"dir", "node-deps", "error", err)
	}

	p.capTopLevelDirsRoot(ctx, scRoot, "node-deps",
		cfg.NodeDepsHighMark, cfg.NodeDepsLowMark, true, log)
}
