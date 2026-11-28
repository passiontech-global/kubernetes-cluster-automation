// atomic.go — the WriteFileAtomic convenience family ported verbatim
// from node-host-agent's platform/hostutil: the tmp+rename atomic
// contract every watchdog state/prom file relies on, plus the
// EBUSY/EXDEV bind-mount fallback to a direct fsync'd write.
package fsx

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// renameFallbackLogged remembers which paths already warned about the
// direct-write fallback — one line per path per process (a
// bind-mounted hosts file takes the fallback on every render and
// would spam the log). The map is size-capped at
// renameFallbackLogCap distinct paths: past the cap, new paths log
// nothing (the map is only a log de-duplicator, never worth unbounded
// growth on hosts with churny target paths).
const renameFallbackLogCap = 1024

// bindMountMemoCap caps bindMountMemo alongside renameFallbackLogCap.
const bindMountMemoCap = renameFallbackLogCap

type bindMountEntry struct {
	renamePtr uintptr
	renameGen uint64
	id        fileIdentity
}

var (
	renameFallbackMu     sync.Mutex
	renameFallbackLogged = make(map[string]bool)

	renameSeamMu sync.RWMutex
	renameGen    atomic.Uint64

	bindMountMu   sync.RWMutex
	bindMountMemo = make(map[string]bindMountEntry)
)

// SetRenameFile swaps RenameFile under lock and bumps the memoization
// generation so two closures created by the same factory function never
// alias in bindMountMemo and parallel callers stay race-free. It returns
// a restore function suitable for t.Cleanup.
func SetRenameFile(fn func(oldpath, newpath string) error) func() {
	renameSeamMu.Lock()
	prev := RenameFile
	RenameFile = fn
	renameGen.Add(1)
	renameSeamMu.Unlock()
	return func() {
		renameSeamMu.Lock()
		RenameFile = prev
		renameGen.Add(1)
		renameSeamMu.Unlock()
	}
}

func currentRenameSig() (uintptr, uint64) {
	renameSeamMu.RLock()
	fn := RenameFile
	gen := renameGen.Load()
	renameSeamMu.RUnlock()
	if fn == nil {
		return 0, gen
	}
	return reflect.ValueOf(fn).Pointer(), gen
}

// memoizedDirectWrite services a WriteFileAtomic* call whose target
// has a memoized bind-mount EBUSY: re-validate the fingerprint, run
// write (the direct fsync'd fallback), then re-stamp the entry —
// check, write and re-stamp all under bindMountMu so a concurrent
// writer can never stat between our write and our re-stamp and
// mistake our own size/mtime bump for a replaced file (that would
// drop the memo and burn a doomed rename). handled=false means no
// usable entry — the caller falls through to the stage+rename path.
// A write error, a vanished target, or a mid-write inode swap all
// evict: the next call re-probes rename(2) instead of trusting a
// fingerprint that no longer describes what sits at path.
//
// The critical section is one mutex hold, so memoized-path writes
// serialize — fine: only bind-mounted files (a handful per node,
// written once per sweep) ever reach it, and their direct writes
// were never atomic anyway.
func memoizedDirectWrite(cleanPath string, rptr uintptr, rgen uint64, write func() error) (bool, error) {
	// Fast path: the overwhelming majority of WriteFileAtomic* calls
	// hit paths with no memo entry — an RLock map probe is the only
	// cost they pay.
	bindMountMu.RLock()
	_, memoized := bindMountMemo[cleanPath]
	bindMountMu.RUnlock()
	if !memoized {
		return false, nil
	}

	bindMountMu.Lock()
	defer bindMountMu.Unlock()
	entry, ok := bindMountMemo[cleanPath]
	if !ok {
		return false, nil
	}
	curID, statOK := statFileIdentity(cleanPath)
	if entry.renamePtr != rptr || entry.renameGen != rgen || !statOK || curID != entry.id {
		// Stale entry: RenameFile swapped, target replaced or
		// removed — drop it and let the caller re-probe through the
		// atomic path.
		delete(bindMountMemo, cleanPath)
		return false, nil
	}
	if err := write(); err != nil {
		delete(bindMountMemo, cleanPath)
		return true, err
	}
	// Re-stamp the post-write fingerprint — the direct write just
	// bumped size/mtime, so keeping the old stamp would read as a
	// replacement on the next call. dev+ino must still match the
	// validated entry: if they don't, the file was swapped while we
	// wrote it and the memo must not vouch for the new inode.
	if id, ok := statFileIdentity(cleanPath); ok &&
		id.dev == entry.id.dev && id.ino == entry.id.ino {
		bindMountMemo[cleanPath] = bindMountEntry{renamePtr: rptr, renameGen: rgen, id: id}
	} else {
		delete(bindMountMemo, cleanPath)
	}
	return true, nil
}

func memoizeBindMount(cleanPath string, rptr uintptr, rgen uint64) {
	id, ok := statFileIdentity(cleanPath)
	if !ok {
		return
	}
	bindMountMu.Lock()
	defer bindMountMu.Unlock()
	if _, exists := bindMountMemo[cleanPath]; !exists && len(bindMountMemo) >= bindMountMemoCap {
		return
	}
	bindMountMemo[cleanPath] = bindMountEntry{renamePtr: rptr, renameGen: rgen, id: id}
}

// warnRenameFallback emits the once-per-path fallback warning.
func warnRenameFallback(path string, err error) {
	renameFallbackMu.Lock()
	defer renameFallbackMu.Unlock()
	if renameFallbackLogged[path] {
		return
	}
	if len(renameFallbackLogged) >= renameFallbackLogCap {
		return
	}
	renameFallbackLogged[path] = true
	logx.For("fsx").Warn("atomic rename refused (bind-mounted "+
		"target?) — falling back to direct fsync'd write",
		"path", path, "error", err)
}

// WriteFileAtomic writes content via a tmp file in the same dir +
// rename — the atomic-copy contract the watchdog state/prom files
// rely on (no torn reads mid-write). The tmp name uses the
// ".tmp-<base>-*" convention: the leading dot keeps it out of
// hostmetrics' state-* scan — a "state-foo.tmp" file would surface as
// a phantom watchdog_state series that then sits at 0 forever — and
// CreateTemp's random suffix gives concurrent writers (workerhygiene
// / controllerhygiene / nethealth / hostmetrics all stamp the same
// last-run/latch files) a private staging file instead of clobbering
// one shared ".tmp-<base>" (truncated or ENOENT-renamed payloads).
// The payload is fsynced before the rename and the parent dir after
// it (see Opts.DirSync for the durability-alignment note).
//
// rename(2) has one blind spot that matters here: the TARGET of a
// file-level bind mount cannot be renamed over — the kernel returns
// EBUSY — and that is exactly how the DaemonSet mounts
// /host/etc/hosts. EXDEV (tmp and target ever landing on different
// filesystems) shares the fallback. Both degrade to a direct
// write+fsync on the target: the crash-atomicity is lost but the
// write actually lands — strictly better than never writing at all.
func WriteFileAtomic(path, content string) error {
	return writeFileAtomicWith(path, []byte(content), false)
}

// writeFileAtomicWith is the shared core for WriteFileAtomic,
// WriteFileAtomicBytes, and WriteFileAtomicNoSync: same memoized
// bind-mount EBUSY fast-path, same stage+rename Opts, and the same
// EBUSY/EXDEV fallback to a direct write (fsynced + dir-fsynced on
// create unless noSync is set).
func writeFileAtomicWith(path string, data []byte, noSync bool) error {
	cleanPath := filepath.Clean(path)
	rptr, rgen := currentRenameSig()
	directWrite := func() error {
		// The fallback must honor NoSync too — a sync on the
		// bind-mount branch would sneak fsync back onto every
		// bind-mounted .prom render.
		return writeFileDirect(cleanPath, data, !noSync, !noSync)
	}
	if handled, err := memoizedDirectWrite(cleanPath, rptr, rgen, directWrite); handled {
		return err
	}
	opts := Opts{
		Stage: StageTempPattern(".tmp-" + filepath.Base(path) + "-*"),
		Mode:  0o644,
	}
	if noSync {
		opts.NoSync = true
	} else {
		opts.DirSync = true
	}
	err := WriteFile(path, data, opts)
	if err == nil {
		return nil
	}
	if !isBindMountRenameErr(err) {
		return err
	}
	warnRenameFallback(cleanPath, err)
	if derr := directWrite(); derr != nil {
		return derr
	}
	if isBindMountEBUSYErr(err) {
		memoizeBindMount(cleanPath, rptr, rgen)
	}
	return nil
}

// writeFileDirect is the shared direct-write core behind
// WriteFileDirect, WriteFileDirectNoSync, and WriteFileAtomic*'s
// EBUSY/EXDEV fallback: open/truncate in place, write data, optionally
// fsync the file (syncFile), and propagate Close errors only when
// write+sync succeeded. When dirSyncOnCreate is true and the target
// did not exist beforehand (EXDEV on an absent target), the parent
// directory is fsynced too to match WriteFile's DirSync contract.
func writeFileDirect(path string, data []byte, syncFile, dirSyncOnCreate bool) error {
	created := false
	if dirSyncOnCreate {
		_, statErr := os.Lstat(path)
		created = os.IsNotExist(statErr)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	var werr error
	if n, err := f.Write(data); err != nil {
		werr = err
	} else if n < len(data) {
		werr = io.ErrShortWrite
	} else if syncFile {
		if err := f.Sync(); err != nil {
			werr = err
		}
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil && created {
		if d, derr := os.Open(filepath.Dir(path)); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return werr
}

// WriteFileDirect writes content straight onto path with an fsync —
// the WriteFileAtomic fallback when rename(2) is refused. Truncates
// in place, so a crash can leave a partial file; only used where
// rename is provably impossible.
func WriteFileDirect(path, content string) error {
	return writeFileDirect(path, []byte(content), true, false)
}

// WriteFileDirectNoSync is WriteFileDirect minus the fsync — the
// WriteFileAtomicNoSync fallback when rename(2) is refused: a NoSync
// writer must not sneak a Sync() onto the bind-mount branch either.
func WriteFileDirectNoSync(path, content string) error {
	return writeFileDirect(path, []byte(content), false, false)
}

// WriteFileAtomicBytes is WriteFileAtomic for callers holding []byte.
// The payload passes straight through — no []byte→string→[]byte round
// trip, so a byte-slice writer pays no conversion copies at all.
func WriteFileAtomicBytes(path string, data []byte) error {
	return writeFileAtomicWith(path, data, false)
}

// WriteFileAtomicNoSync is WriteFileAtomic minus the durability
// fsyncs — same tmp+rename atomicity (Opts.NoSync), for the
// ephemeral files the next cycle rewrites anyway: .prom textfiles,
// apibe-gap-*, last-run. A crash can lose the newest content; the
// file is never torn.
func WriteFileAtomicNoSync(path, content string) error {
	return writeFileAtomicWith(path, []byte(content), true)
}
