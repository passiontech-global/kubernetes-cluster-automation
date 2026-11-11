// Package fsx is libs/hostkit's atomic file writer: a same-dir
// staging file + rename, fsynced so readers never see a torn file and
// a crash never promotes unflushed bytes. It is ported verbatim from
// the node-host-agent's hostutil.WriteAtomic (the canonical
// implementation) so hostutil can delegate here without behavior
// drift; the knob set (Opts) mirrors hostutil.AtomicOpts 1:1.
//
// Like the rest of libs/hostkit this package is stdlib-only
// (depguard: hostkit-is-leaf) — the EBUSY/EXDEV bind-mount fallback
// stays above it in hostutil, which detects those errors and retries.
package fsx

import (
	"io"
	"os"
	"path/filepath"
)

// RenameFile is the rename(2) seam — tests stub it to inject rename
// failures (sweeping the staging file) without a real filesystem
// fault. Same seam hostutil exposes, so its delegation can keep its
// existing stubs pointed here.
var RenameFile = os.Rename

// Opts tunes WriteFile — the shared staging→fsync→rename core. The
// knobs that legitimately differ between consumers are the staging
// name shape and the page-cache hook; the durability contract (payload
// fsync before rename, dir fsync after) is uniform.
type Opts struct {
	// Stage opens the staging file the rename will promote to path.
	// It must create the file in the dir it is handed (the target's
	// parent — same filesystem is what makes the rename atomic).
	// StageTempPattern is the one shape in use: CreateTemp with a "*"
	// pattern — a private random staging name per concurrent writer
	// (a fixed staging name would let a crash-restart's two writers
	// truncate each other's stage mid-write). Nil Stage defaults to
	// exactly that shape for the target's base name.
	Stage func(dir string) (*os.File, error)
	// Mode is forced onto the staging file before sync+rename —
	// CreateTemp stages 0600 and an OpenFile create-mode is
	// umask-masked, but every consumer of these files
	// (node_exporter, systemd units) reads them as another user.
	// Applied verbatim: zero makes the file mode 0 (unreadable), so
	// callers always set it, matching hostutil's contract.
	Mode os.FileMode
	// DirSync fsyncs the target's parent directory after a
	// successful rename, so the directory entry itself is durable.
	// Without it a crash after the rename can lose the file entirely
	// (old name already unlinked, new entry not yet flushed). The
	// directory open is best-effort (a dir that vanished between
	// rename and sync must not fail an already-installed write); a
	// Sync failure IS reported.
	DirSync bool
	// AfterSync, when set, runs after the payload fsync and before
	// Close — converge passes pagecache.Drop so a staged binary's
	// cache charge does not outlive the write (post-Sync the pages
	// are clean, so DONTNEED drops them outright). Runs regardless of
	// NoSync.
	AfterSync func(f *os.File)
	// NoSync skips BOTH fsyncs (payload and DirSync) — the
	// CreateTemp+Chmod+Rename atomicity contract is unchanged, so
	// readers still never see a torn file; only crash durability is
	// dropped. Reserved for ephemeral files a crash may lose
	// harmlessly because the next cycle rewrites them anyway:
	// node-exporter .prom textfiles, last-run stamps. Config files
	// under /etc and latch/state files keep the durable path — a
	// lost latch reads as "condition cleared".
	NoSync bool
}

// StageTempPattern returns a Stage that CreateTemps a uniquely
// named staging file in dir — pattern keeps the "*" placeholder
// (CreateTemp replaces it with a random suffix).
func StageTempPattern(pattern string) func(string) (*os.File, error) {
	return func(dir string) (*os.File, error) { return os.CreateTemp(dir, pattern) }
}

// WriteFile installs content at path via a same-dir staging file
// + rename. The payload fsync BEFORE the rename closes the crash
// window where the rename lands but the bytes were never flushed; a
// positive DirSync makes the rename itself durable. Every failure
// path sweeps the staging file; a short write is a failed write.
func WriteFile(path string, data []byte, opts Opts) error {
	dir := filepath.Dir(path)
	stage := opts.Stage
	if stage == nil {
		// The leading-dot ".tmp-<base>-*" convention keeps a staged
		// file out of glob/scans that match the target name, and
		// CreateTemp's random suffix gives concurrent writers a
		// private staging file instead of clobbering one shared
		// ".tmp-<base>" (truncated or ENOENT-renamed payloads).
		stage = StageTempPattern(".tmp-" + filepath.Base(path) + "-*")
	}
	tmp, err := stage(dir)
	if err != nil {
		return err
	}
	// A short write is a failed write — n < len(data) means a
	// truncated file would be promoted by the rename below. Every
	// failure path must remove the staging file; a leaked staging
	// file would sit in the state dir forever.
	if n, werr := tmp.Write(data); werr != nil || n < len(data) {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		if werr == nil {
			werr = io.ErrShortWrite
		}
		return werr
	}
	return Promote(tmp, path, opts)
}

// Promote finishes a staged file's install: mode pin, payload fsync,
// AfterSync hook, Close, rename (through the RenameFile seam), and
// the DirSync — the exact WriteFile core from "the bytes are in the
// staging file" onward. It exists for STREAMING writers (an HTTP
// body, a tar member, a copied binary) that must write the stage
// themselves and only then hand it over; WriteFile is Promote plus
// stage-and-write. Sweeps the staging file on every failure path,
// like WriteFile. Opts.Stage is ignored here — the caller owns the
// stage.
func Promote(f *os.File, path string, opts Opts) error {
	tmpName := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmpName)
		return err
	}
	// Force the final mode before sync+rename (see Opts.Mode).
	if err := f.Chmod(opts.Mode); err != nil {
		return fail(err)
	}
	// fsync the payload before the rename — without it a crash can
	// leave a renamed-but-empty file behind. NoSync consumers opt
	// out (see Opts.NoSync).
	if !opts.NoSync {
		if err := f.Sync(); err != nil {
			return fail(err)
		}
	}
	if opts.AfterSync != nil {
		opts.AfterSync(f)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := RenameFile(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if opts.DirSync && !opts.NoSync {
		if d, err := os.Open(filepath.Dir(path)); err == nil {
			err = d.Sync()
			_ = d.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
