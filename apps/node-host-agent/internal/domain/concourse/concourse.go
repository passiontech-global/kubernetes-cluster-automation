// Package concourse holds the shared Concourse worker cache contract
// and O_NOFOLLOW fd-pinned permission enforcement shared between
// ops/concourseinit (pod init scaffold) and subsystem/concoursecache
// (host-side PVC pruner).
package concourse

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// SharedCacheName is the shared-cache directory inside each worker workDir.
	SharedCacheName = "shared-cache"

	// CacheOwner is the host uid+gid that container root (0) of unprivileged
	// task containers maps to through the userns (uidMappings hostID:4294967294).
	CacheOwner = 4294967294

	// CachePerm is forced on shared-cache and its first-level entries so
	// unprivileged jobs can write through the /shared-cache bind mount.
	CachePerm os.FileMode = 0o777
)

// ChownFD applies ownership to an already-opened fd. Nil defaults to DefaultChownFD.
type ChownFD func(path string, fd, uid, gid int) error

// DefaultChownFD applies uid/gid directly on the open fd via unix.Fchown.
func DefaultChownFD(_ string, fd, uid, gid int) error {
	return unix.Fchown(fd, uid, gid)
}

// WithNoFollowFD opens path with O_NOFOLLOW|O_NONBLOCK, verifies via
// fstat that the held fd is a plain directory (or regular file when
// allowFile is true), and invokes fn on that fd so callers avoid
// Lstat-then-chown/chmod symlink races. O_NONBLOCK is load-bearing:
// a FIFO substituted at path must not block the OS thread in open()
// before fstat can reject it (unix.Open is not Go-netpoller aware).
func WithNoFollowFD(path string, allowFile bool, fn func(fd int, st *unix.Stat_t) error) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open %s (nofollow): %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("fstat %s: %w", path, err)
	}
	if err := checkFDType(path, allowFile, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := fn(fd, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func checkFDType(target string, allowFile bool, st *unix.Stat_t) error {
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return nil
	case unix.S_IFREG:
		if !allowFile {
			return fmt.Errorf("%s: not a directory (mode %o)", target, st.Mode&unix.S_IFMT)
		}
		return nil
	default:
		if allowFile {
			return fmt.Errorf("%s: not a dir or regular file (mode %o)", target, st.Mode&unix.S_IFMT)
		}
		return fmt.Errorf("%s: not a directory (mode %o)", target, st.Mode&unix.S_IFMT)
	}
}

// WithNoFollowRootFD resolves rel inside root without following ANY
// symbolic link (neither intermediate components nor the leaf, whether
// escaping or intra-root, per Go's root_unix.go doInRoot caveat), opens
// the leaf via root.OpenFile + unix.Openat with O_RDONLY|O_CLOEXEC|
// O_NOFOLLOW|O_NONBLOCK, verifies via fstat that the held fd is a plain
// directory (or regular file when allowFile is true), and invokes fn on
// that fd.
func WithNoFollowRootFD(root *os.Root, rel string, allowFile bool, fn func(fd int, st *unix.Stat_t) error) error {
	if root == nil {
		return errors.New("concourse: nil root")
	}
	clean := path.Clean(filepath.ToSlash(rel))
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("invalid relative path %q", rel)
	}
	rootFile, err := root.OpenFile(".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open root %s: %w", rel, err)
	}
	if clean == "." {
		defer func() { _ = rootFile.Close() }()
		fd := int(rootFile.Fd())
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fmt.Errorf("fstat %s: %w", rel, err)
		}
		if err := checkFDType(rel, allowFile, &st); err != nil {
			return err
		}
		return fn(fd, &st)
	}

	curFd := int(rootFile.Fd())
	closeCur := func() {
		if rootFile != nil {
			_ = rootFile.Close()
			rootFile = nil
		} else if curFd >= 0 {
			_ = unix.Close(curFd)
		}
		curFd = -1
	}

	parts := strings.Split(clean, "/")
	for _, seg := range parts[:len(parts)-1] {
		nextFd, oerr := unix.Openat(curFd, seg, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
		closeCur()
		if oerr != nil {
			return fmt.Errorf("openat dir %s (%s): %w", rel, seg, oerr)
		}
		curFd = nextFd
	}
	base := parts[len(parts)-1]
	fd, err := unix.Openat(curFd, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	closeCur()
	if err != nil {
		return fmt.Errorf("openat %s (nofollow): %w", rel, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("fstat %s: %w", rel, err)
	}
	if err := checkFDType(rel, allowFile, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := fn(fd, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close %s: %w", rel, err)
	}
	return nil
}

// EnforcePermsRootFD opens rel inside root with O_NOFOLLOW (via
// WithNoFollowRootFD) and applies uid/gid (when >=0) and mode directly
// on the held file descriptor.
func EnforcePermsRootFD(root *os.Root, rel string, allowFile bool, uid, gid int, mode os.FileMode, chown ChownFD) error {
	if chown == nil {
		chown = DefaultChownFD
	}
	return WithNoFollowRootFD(root, rel, allowFile, func(fd int, _ *unix.Stat_t) error {
		if uid >= 0 || gid >= 0 {
			if err := chown(rel, fd, uid, gid); err != nil {
				return fmt.Errorf("chown %s: %w", rel, err)
			}
		}
		if err := unix.Fchmod(fd, uint32(mode)); err != nil {
			return fmt.Errorf("chmod %s: %w", rel, err)
		}
		return nil
	})
}

// EnforcePermsFD opens path with O_NOFOLLOW (via WithNoFollowFD) and applies
// uid/gid (when >=0) and mode directly on the held file descriptor.
func EnforcePermsFD(path string, allowFile bool, uid, gid int, mode os.FileMode, chown ChownFD) error {
	if chown == nil {
		chown = DefaultChownFD
	}
	return WithNoFollowFD(path, allowFile, func(fd int, _ *unix.Stat_t) error {
		if uid >= 0 || gid >= 0 {
			if err := chown(path, fd, uid, gid); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		}
		if err := unix.Fchmod(fd, uint32(mode)); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
		return nil
	})
}
