// fsutil.go — the du/find equivalents the buckets are built on:
// Lstat'd dir checks, allocated-block disk usage (du -sk semantics),
// oldest-first candidate listings and the chmod -R u+w walker.
package concoursecache

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// enforceDirPermsFD applies uid/gid + mode to a directory WITHOUT
// re-resolving the path: the dir is opened O_NOFOLLOW (a swapped-in
// symlink fails the open instead of being dereferenced), fstat'd to
// confirm the fd still is a plain directory, then Fchown/Fchmod run
// on the held fd. The Lstat-then-Chown pattern had a swap window —
// on a CI-controlled 0777 tree an actor can replace a verified
// entry with `<entry> -> /etc` between the check and the chmod,
// turning the root perm pass into a host-file privilege gadget.
// withDirFD opens path with O_NOFOLLOW, verifies via fstat that the held
// fd is a directory, and invokes fn on that fd so callers never suffer
// an Lstat-then-chown/chmod symlink swap race.
func withDirFD(path string, fn func(fd int, st *unix.Stat_t) error) error {
	fd, err := unix.Open(path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s: not a directory (mode %o)", path, st.Mode&unix.S_IFMT)
	}
	return fn(fd, &st)
}

func enforceDirPermsFD(path string, uid, gid int, mode os.FileMode) error {
	return withDirFD(path, func(fd int, _ *unix.Stat_t) error {
		if uid >= 0 || gid >= 0 {
			if err := unix.Fchown(fd, uid, gid); err != nil {
				return err
			}
		}
		return unix.Fchmod(fd, uint32(mode))
	})
}

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
// allocated blocks (st_blocks×512). A sparse file's st.Blocks is 0
// and that is exactly what du counts for it — falling back to
// apparent size here would let one huge sparse file inflate a trim
// accumulator past the size marks in a single step (the totals it is
// compared against are all block-based, so units must never mix).
func entryBlocks(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
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
// `find -type f -printf '%T@ %s %p\n' | sort -n`. size carries ALLOCATED
// blocks (entryBlocks), not apparent size: the trim accumulators compare
// it against diskUsage totals and the size marks, which are all du-style
// st_blocks×512 — mixing units would let sparse files (huge apparent
// size, tiny footprint) blow the cap math and misreport bytesFreed.
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
			out = append(out, cacheFile{
				path:    path,
				size:    int64(entryBlocks(info)),
				modTime: info.ModTime(),
			})
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

// removeTree is rm -rf for cache trees: a bare RemoveAll first —
// the common writable-tree case needs no chmod walk at all (the old
// makeWritable-everything + RemoveAll walked each tree 3×). Only
// when removal FAILS does it walk once, u+w-ing DIRECTORIES only
// (removal permission lives on the containing dir — a file's own
// mode never matters for rm), then retries RemoveAll once.
func removeTree(root string) error {
	if err := os.RemoveAll(root); err == nil {
		return nil
	}
	makeWritableDirs(root)
	return os.RemoveAll(root)
}

// makeWritableDirs adds u+w to every DIRECTORY under root —
// node-deps subdirs can be read-only (bun install chmod a-w), which
// defeats rm -rf. DirEntry.IsDir is Lstat-based and WalkDir never
// descends into symlinked dirs, so links and their targets are
// never touched: os.Chmod follows links, and running as root in a
// CI-owned tree makes a planted `dir -> /etc` a host-chmod gadget.
// Files are skipped — their mode is irrelevant to removal.
func makeWritableDirs(root string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped, never fatal
		}
		if !d.IsDir() {
			return nil
		}
		chmodDirWritableFD(path)
		return nil
	})
}

// chmodDirWritableFD adds u+w to a directory WITHOUT re-resolving
// the path — the path-based os.Chmod had a swap window: on a
// CI-controlled 0777 tree an actor can replace a verified entry
// with `<entry> -> /etc` between WalkDir's Lstat and the chmod,
// turning the root perm pass into a host-file privilege gadget
// (the same class enforceDirPermsFD closes for the perm pass). The
// dir is opened O_NOFOLLOW (a swapped-in symlink fails the open),
// fstat'd to confirm the fd still is a plain directory, then
// Fchmod'd — only the held inode's mode ever changes.
func chmodDirWritableFD(path string) {
	_ = withDirFD(path, func(fd int, st *unix.Stat_t) error {
		return unix.Fchmod(fd, (st.Mode&0o7777)|0o200)
	})
}
