//go:build unix

// stat_unix.go — the unix half of the platform split: rename(2)
// errno classification and the syscall.Stat_t stat fingerprint.
// stat_other.go carries the !unix stubs so the package compiles on
// every GOOS.
package fsx

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// isBindMountRenameErr reports whether a rename failure is the
// file-level bind-mount blind spot (EBUSY — the DaemonSet's
// /host/etc/hosts shape) or a cross-filesystem EXDEV, both of which
// degrade to the direct-write fallback in WriteFileAtomic*.
func isBindMountRenameErr(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV)
}

// isBindMountEBUSYErr reports specifically whether a rename failure
// is EBUSY (bind-mounted target), which WriteFileAtomic* memoizes so
// subsequent writes skip the doomed tmp+fsync+rename cycle.
func isBindMountEBUSYErr(err error) bool {
	return errors.Is(err, syscall.EBUSY)
}

// fileIdentity fingerprints one generation of the file at a path:
// dev+ino name the inode, size+mtime name the content generation.
// dev+ino ALONE are not enough — an unlink+recreate in the same
// directory can hand the new file the just-freed inode (the
// allocator reuses it), which is exactly the bind-mount replacement
// the memo must detect; size+mtime almost always differ across a
// replace, and the memo re-stamps them after every direct write so
// our own writes never read as a replacement.
type fileIdentity struct {
	dev   uint64
	ino   uint64
	size  int64
	mtime int64 // UnixNano
}

// statFileIdentity fingerprints path for the bind-mount memo — see
// fileIdentity for why the fingerprint is wider than dev+ino.
func statFileIdentity(path string) (fileIdentity, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileIdentity{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{
		dev:   st.Dev,
		ino:   st.Ino,
		size:  fi.Size(),
		mtime: fi.ModTime().UnixNano(),
	}, true
}

// FileStatKey fingerprints a file's identity+generation WITHOUT
// reading it: dev, inode, size and mtime. Every writer in this
// tree stages via atomic rename (WriteAtomic family), which always
// lands a NEW inode — so an unchanged key proves the bytes cannot
// have changed and callers may skip re-reading/re-parsing the file
// (CA bundles, X.509 certs, rendered confs all re-stat per cycle).
// A missing file returns the os.Stat error verbatim.
func FileStatKey(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	// os.Stat results expose *syscall.Stat_t on unix — the x/sys
	// unix.Stat_t is a distinct type and the assertion would always
	// fail.
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("stat %s: unexpected FileInfo.Sys type %T", path, fi.Sys())
	}
	return fmt.Sprintf("%d:%d:%d:%d",
		st.Dev, st.Ino, fi.Size(), fi.ModTime().UnixNano()), nil
}
