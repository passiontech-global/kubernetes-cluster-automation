// host.go — managed-file verbs over a HostRoot: sha256-compared
// atomic writes, managed removes, dir/exists probes. The verbs return
// errors; metric and cycle-error attribution stay with the caller.
package converge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
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
	// The stage→write→fsync→rename sequence is hostutil.WriteAtomic —
	// one implementation shared with WriteFileAtomic/promfile.Write.
	// The staging name is a UNIQUE per-write CreateTemp draw under the
	// target dir ("<base>.converge.tmp-<random>" — files.go's
	// installMember pattern): a FIXED stage name let two concurrent
	// writers (agent crash-restart mid-cycle — old process between
	// open and rename while the new process starts) open/truncate the
	// SAME tmp, and the old process's fsync+rename would then publish
	// the new process's partial bytes. Unique stages make each writer
	// rename only bytes it wrote itself; last rename wins cleanly, and
	// a crashed writer's leaked stage is still recognizable for the
	// ".converge.tmp" sweep (tests/ops glob that infix, not a fixed
	// name). Mode is the caller's — or the existing file's — perm
	// bits; AfterSync evicts the just-written pages so a staged
	// binary's cache charge does not outlive the write (see pagecache
	// doc; post-Sync the pages are clean, so DONTNEED drops them
	// outright). DirSync failure now surfaces as an error (the shared
	// core reports it; this verb used to swallow it).
	if err := fsx.WriteFile(dst, content, fsx.Opts{
		Stage:     fsx.StageTempPattern(filepath.Base(dst) + ".converge.tmp-*"),
		Mode:      mode,
		AfterSync: pagecache.Drop,
		DirSync:   true,
	}); err != nil {
		return fail(err)
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
