// fsutil.go — the du/find equivalents the buckets are built on:
// *os.Root-pinned dir checks (no symlink escape), allocated-block
// disk usage (du -sk semantics), oldest-first candidate listings,
// O_NOFOLLOW unlink/rmdir and the chmod -R u+w walker.
package concoursecache

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/concourse"
)

// openDirRootNoSymlink verifies via Lstat + OpenRoot + SameFile that
// dirPath is a real directory (never a symlink) and returns a handle
// pinned to that inode.
func openDirRootNoSymlink(dirPath string) (*os.Root, error) {
	lfi, err := os.Lstat(dirPath)
	if err != nil {
		return nil, err
	}
	if lfi.Mode()&os.ModeSymlink != 0 || !lfi.IsDir() {
		return nil, fmt.Errorf("%s: not a real directory", dirPath)
	}
	root, err := os.OpenRoot(dirPath)
	if err != nil {
		return nil, err
	}
	rfi, err := root.Stat(".")
	if err != nil || !os.SameFile(lfi, rfi) {
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s: directory swapped during open", dirPath)
	}
	return root, nil
}

// openSubRootNoSymlink opens rel inside parent without following an
// escaping OR intra-root symlink at rel (Lstat + OpenRoot + SameFile).
func openSubRootNoSymlink(parent *os.Root, rel string) (*os.Root, error) {
	lfi, err := parent.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if lfi.Mode()&os.ModeSymlink != 0 || !lfi.IsDir() {
		return nil, fmt.Errorf("%s: not a real directory", rel)
	}
	sub, err := parent.OpenRoot(rel)
	if err != nil {
		return nil, err
	}
	rfi, err := sub.Stat(".")
	if err != nil || !os.SameFile(lfi, rfi) {
		_ = sub.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s: directory swapped during open", rel)
	}
	return sub, nil
}

func enforceDirPermsRootFD(root *os.Root, rel string, uid, gid int, mode os.FileMode) error {
	return concourse.EnforcePermsRootFD(root, rel, false, uid, gid, mode, nil)
}

// unlinkRootNoFollow removes rel inside root without following ANY
// symlink in intermediate components or at the leaf.
func unlinkRootNoFollow(root *os.Root, rel string, flags int) error {
	clean := path.Clean(filepath.ToSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("invalid relative path %q", rel)
	}
	dir, base := path.Dir(clean), path.Base(clean)
	return concourse.WithNoFollowRootFD(root, dir, false, func(parentFd int, _ *unix.Stat_t) error {
		return unix.Unlinkat(parentFd, base, flags)
	})
}

// cacheFile is one prune candidate: path (root-relative) + mtime + allocated blocks.
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
func diskUsage(ctx context.Context, rootPath string) uint64 {
	root, err := openDirRootNoSymlink(rootPath)
	if err != nil {
		return 0
	}
	defer func() { _ = root.Close() }()
	return diskUsageRoot(ctx, root)
}

func diskUsageRoot(ctx context.Context, root *os.Root) uint64 {
	var total uint64
	_ = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		info, err := d.Info()
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", rel, "error", err)
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
func diskUsageByTopDir(ctx context.Context, rootPath string) (total uint64, perDir map[string]uint64) {
	root, err := openDirRootNoSymlink(rootPath)
	if err != nil {
		return 0, map[string]uint64{}
	}
	defer func() { _ = root.Close() }()
	return diskUsageByTopDirRoot(ctx, root)
}

func diskUsageByTopDirRoot(ctx context.Context, root *os.Root) (total uint64, perDir map[string]uint64) {
	perDir = map[string]uint64{}
	_ = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		info, err := d.Info()
		if err != nil {
			logger().Debug("du: unreadable entry skipped",
				"path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		sz := entryBlocks(info)
		total += sz
		if rel != "." {
			top := rel
			if i := strings.IndexByte(top, '/'); i >= 0 {
				top = top[:i]
			}
			perDir[top] += sz
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
func filesByAge(ctx context.Context, rootPath string) []cacheFile {
	root, err := openDirRootNoSymlink(rootPath)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	return filesByAgeRoot(ctx, root)
}

func filesByAgeRoot(ctx context.Context, root *os.Root) []cacheFile {
	var out []cacheFile
	_ = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			logger().Debug("find: unreadable entry skipped",
				"path", rel, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			out = append(out, cacheFile{
				path:    rel,
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
func topLevelDirsByAge(rootPath string) []cacheFile {
	root, err := openDirRootNoSymlink(rootPath)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	return topLevelDirsByAgeRoot(root)
}

func topLevelDirsByAgeRoot(root *os.Root) []cacheFile {
	var out []cacheFile
	if entries, err := fs.ReadDir(root.FS(), "."); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if info, err := e.Info(); err == nil {
				out = append(out, cacheFile{
					path:    e.Name(),
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
func removeTree(targetPath string) error {
	parent, err := openDirRootNoSymlink(filepath.Dir(targetPath))
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return removeTreeRoot(parent, filepath.Base(targetPath))
}

func removeTreeRoot(parent *os.Root, rel string) error {
	if err := parent.RemoveAll(rel); err == nil {
		return nil
	}
	makeWritableDirsRoot(parent, rel)
	return parent.RemoveAll(rel)
}

// makeWritableDirs adds u+w to every DIRECTORY under root —
// node-deps subdirs can be read-only (bun install chmod a-w), which
// defeats rm -rf. WalkDir over *os.Root never descends into symlinked
// dirs, and chmodDirWritableRootFD opens each dir via O_NOFOLLOW
// relative to the pinned root so neither escaping nor intra-root
// symlinks can ever be followed or chmodded.
func makeWritableDirs(rootPath string) {
	parent, err := openDirRootNoSymlink(filepath.Dir(rootPath))
	if err != nil {
		return
	}
	defer func() { _ = parent.Close() }()
	makeWritableDirsRoot(parent, filepath.Base(rootPath))
}

func makeWritableDirsRoot(parent *os.Root, rel string) {
	sub, err := openSubRootNoSymlink(parent, rel)
	if err != nil {
		return
	}
	defer func() { _ = sub.Close() }()
	_ = fs.WalkDir(sub.FS(), ".", func(subRel string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped, never fatal
		}
		if !d.IsDir() {
			return nil
		}
		chmodDirWritableRootFD(sub, subRel)
		return nil
	})
}

// chmodDirWritableRootFD adds u+w to a directory WITHOUT re-resolving
// the path or following any symlink (escaping or intra-root) via
// concourse.WithNoFollowRootFD + unix.Fchmod.
func chmodDirWritableRootFD(root *os.Root, rel string) {
	_ = concourse.WithNoFollowRootFD(root, rel, false, func(fd int, st *unix.Stat_t) error {
		return unix.Fchmod(fd, (st.Mode&0o7777)|0o200)
	})
}
