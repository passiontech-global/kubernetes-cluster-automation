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
// would spam the log).
var renameFallbackLogged sync.Map

// warnRenameFallback emits the once-per-path fallback warning.
func warnRenameFallback(path string, err error) {
	if _, logged := renameFallbackLogged.LoadOrStore(path, true); !logged {
		logx.For("fsx").Warn("atomic rename refused (bind-mounted "+
			"target?) — falling back to direct fsync'd write",
			"path", path, "error", err)
	}
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
	err := WriteFile(path, []byte(content), Opts{
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
	return WriteFileDirect(path, content)
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

// WriteFileAtomicBytes is WriteFileAtomic for callers holding []byte.
func WriteFileAtomicBytes(path string, data []byte) error {
	return WriteFileAtomic(path, string(data))
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
	return WriteFileDirect(path, content)
}
