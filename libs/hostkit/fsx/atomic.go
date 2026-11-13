// atomic.go — the WriteFileAtomic convenience family ported verbatim
// from node-host-agent's platform/hostutil: the tmp+rename atomic
// contract every watchdog state/prom file relies on, plus the
// EBUSY/EXDEV bind-mount fallback to a direct fsync'd write.
package fsx

import (
	"os"
	"path/filepath"
	"sync"

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

var (
	renameFallbackMu     sync.Mutex
	renameFallbackLogged = make(map[string]bool)
)

// warnRenameFallback emits the once-per-path fallback warning.
func warnRenameFallback(path string, err error) {
	renameFallbackMu.Lock()
	if _, logged := renameFallbackLogged[path]; !logged {
		if len(renameFallbackLogged) >= renameFallbackLogCap {
			renameFallbackMu.Unlock()
			return
		}
		renameFallbackLogged[path] = true
	}
	renameFallbackMu.Unlock()
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
	return writeFileAtomic(path, []byte(content))
}

// writeFileAtomic is the bytes-taking core WriteFileAtomic and
// WriteFileAtomicBytes share: the same stage+rename Opts, the same
// EBUSY/EXDEV fallback to a direct fsync'd write. One payload copy,
// paid only when the caller holds a string.
func writeFileAtomic(path string, data []byte) error {
	err := WriteFile(path, data, Opts{
		Stage:   StageTempPattern(".tmp-" + filepath.Base(path) + "-*"),
		Mode:    0o644,
		DirSync: true,
	})
	if err == nil {
		return nil
	}
	if !isBindMountRenameErr(err) {
		return err
	}
	warnRenameFallback(path, err)
	return writeFileDirectBytes(path, data)
}

// writeFileDirectBytes is WriteFileDirect for a []byte payload — the
// fallback twin of the string form: same open/truncate, same
// write-then-fsync error precedence (Close's error surfaces only
// when write and sync succeeded).
func writeFileDirectBytes(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	var werr error
	if _, err := f.Write(data); err != nil {
		werr = err
	} else if err := f.Sync(); err != nil {
		werr = err
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// WriteFileDirect writes content straight onto path with an fsync —
// the WriteFileAtomic fallback when rename(2) is refused. Truncates
// in place, so a crash can leave a partial file; only used where
// rename is provably impossible.
func WriteFileDirect(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	var werr error
	if _, err := f.WriteString(content); err != nil {
		werr = err
	} else if err := f.Sync(); err != nil {
		werr = err
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// WriteFileDirectNoSync is WriteFileDirect minus the fsync — the
// WriteFileAtomicNoSync fallback when rename(2) is refused: a NoSync
// writer must not sneak a Sync() onto the bind-mount branch either.
func WriteFileDirectNoSync(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	var werr error
	if _, err := f.WriteString(content); err != nil {
		werr = err
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// WriteFileAtomicBytes is WriteFileAtomic for callers holding []byte.
// The payload passes straight through — no []byte→string→[]byte round
// trip, so a byte-slice writer pays no conversion copies at all.
func WriteFileAtomicBytes(path string, data []byte) error {
	return writeFileAtomic(path, data)
}

// WriteFileAtomicNoSync is WriteFileAtomic minus the durability
// fsyncs — same tmp+rename atomicity (Opts.NoSync), for the
// ephemeral files the next cycle rewrites anyway: .prom textfiles,
// apibe-gap-*, last-run. A crash can lose the newest content; the
// file is never torn.
func WriteFileAtomicNoSync(path, content string) error {
	err := WriteFile(path, []byte(content), Opts{
		Stage:  StageTempPattern(".tmp-" + filepath.Base(path) + "-*"),
		Mode:   0o644,
		NoSync: true,
	})
	if err == nil {
		return nil
	}
	if !isBindMountRenameErr(err) {
		return err
	}
	warnRenameFallback(path, err)
	// The fallback must honor NoSync too — WriteFileDirect would
	// sneak the fsync this family exists to skip back onto every
	// bind-mounted .prom render.
	return WriteFileDirectNoSync(path, content)
}
