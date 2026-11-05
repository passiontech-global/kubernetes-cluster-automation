// fsutil.go — the du/find equivalents the buckets are built on:
// Lstat'd dir checks, allocated-block disk usage (du -sk semantics),
// oldest-first candidate listings and the chmod -R u+w walker.
package concoursecache

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

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
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		info, err := d.Info()
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
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
			logger().Debug("du: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		info, err := d.Info()
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
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
		if err != nil {
			logger().Debug("find: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() || !d.Type().IsRegular() {
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
			logger().Debug("chmod -R: unreadable entry skipped",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
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
