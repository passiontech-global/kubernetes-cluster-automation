// host.go — managed-file verbs over a HostRoot: sha256-compared
// atomic writes, managed removes, dir/exists probes. The verbs return
// errors; metric and cycle-error attribution stay with the caller.
package converge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
)

// Host is the managed-file seam a converger writes through: every
// host path joins under Root ("/host" in the agent pod, "/" on the
// standalone deployment) so the same policy code addresses both.
type Host struct {
	Root string
}

// Join roots a host path under Root.
func (h Host) Join(p string) string {
	return filepath.Join(h.Root, p)
}

// WriteManaged writes content to Root+path atomically when it
// differs (sha256). Returns changed. Preserves the existing file's
// mode; mode applies only when creating.
func (h Host) WriteManaged(path string, content []byte, mode os.FileMode) (bool, error) {
	dst := h.Join(path)
	// Streamed hash + pagecache drop: dst can be a staged binary in
	// the tens of MB (self-stage) — os.ReadFile would pull it into
	// the pod's charged page cache every cycle.
	if oldHex, err := pagecache.Sha256File(dst); err == nil {
		nsum := sha256.Sum256(content)
		if oldHex == hex.EncodeToString(nsum[:]) {
			return false, nil
		}
		if st, err := os.Stat(dst); err == nil {
			mode = st.Mode().Perm()
		}
	} else if !os.IsNotExist(err) {
		logger().Warn("converge: read managed file failed", "path", path, "error", err)
		return false, err
	}
	fail := func(err error) (bool, error) {
		logger().Warn("converge: write managed file failed", "path", path, "error", err)
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fail(err)
	}
	tmp := dst + ".converge.tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fail(err)
	}
	// A short write is a failed write — n < len(content) means a
	// truncated file would be promoted by the rename below.
	if n, err := f.Write(content); err != nil || n < len(content) {
		_ = f.Close()
		_ = os.Remove(tmp)
		if err == nil {
			err = io.ErrShortWrite
		}
		return fail(err)
	}
	// fsync BEFORE rename — the content must be durable at the final
	// name, so a crash after rename can never expose a zeroed file.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fail(err)
	}
	// Evict the just-written pages — a staged binary's cache charge
	// outlives the write otherwise (see pagecache doc). After Sync
	// the pages are clean, so DONTNEED drops them outright.
	pagecache.Drop(f)
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fail(err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return fail(err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fail(err)
	}
	// Parent-dir fsync: the rename is only durable once the new
	// directory entry is flushed.
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	logger().Info("converge: wrote managed file", "path", path)
	return true, nil
}

// RemoveManaged deletes Root+path; a missing file is not an error
// and a directory is refused outright (convergers manage files, an
// rm -rf bug would be unrecoverable).
func (h Host) RemoveManaged(path string) (bool, error) {
	dst := h.Join(path)
	fi, err := os.Lstat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			logger().Warn("converge: remove stat failed — treating as absent",
				"path", path, "error", err)
		}
		return false, nil
	}
	if fi.IsDir() {
		logger().Warn("converge: remove refused — path is a dir", "path", path)
		return false, fmt.Errorf("converge: RemoveManaged: %s is a dir", path)
	}
	if err := os.Remove(dst); err != nil {
		logger().Warn("converge: remove file failed", "path", path, "error", err)
		return false, err
	}
	logger().Info("converge: removed file", "path", path)
	return true, nil
}

// EnsureDir is MkdirAll under Root.
func (h Host) EnsureDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(h.Join(path), mode); err != nil {
		logger().Warn("converge: ensure dir failed", "path", path, "error", err)
		return err
	}
	return nil
}

// FileExists reports whether Root+path stats clean.
func (h Host) FileExists(path string) bool {
	_, err := os.Stat(h.Join(path))
	return err == nil
}
