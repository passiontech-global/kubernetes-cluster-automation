// Package concourse holds the shared Concourse worker cache contract
// and O_NOFOLLOW fd-pinned permission enforcement shared between
// ops/concourseinit (pod init scaffold) and subsystem/concoursecache
// (host-side PVC pruner).
package concourse

import (
	"fmt"
	"os"

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

// WithNoFollowFD opens path with O_NOFOLLOW, verifies via fstat that the held
// fd is a plain directory (or regular file when allowFile is true), and
// invokes fn on that fd so callers avoid Lstat-then-chown/chmod symlink races.
func WithNoFollowFD(path string, allowFile bool, fn func(fd int, st *unix.Stat_t) error) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s (nofollow): %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("fstat %s: %w", path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
	case unix.S_IFREG:
		if !allowFile {
			_ = unix.Close(fd)
			return fmt.Errorf("%s: not a directory (mode %o)", path, st.Mode&unix.S_IFMT)
		}
	default:
		_ = unix.Close(fd)
		if allowFile {
			return fmt.Errorf("%s: not a dir or regular file (mode %o)", path, st.Mode&unix.S_IFMT)
		}
		return fmt.Errorf("%s: not a directory (mode %o)", path, st.Mode&unix.S_IFMT)
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
