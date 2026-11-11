// Package hostutil holds small host-level helpers shared by the
// subsystems: atomic file writes (the .tmp-<name> + rename contract
// every watchdog state file relies on), /proc uptime parsing, JSON
// key scans and interface MTU reads. Anything here must stay
// dependency-free and safe to call from scrape-time collectors.
package hostutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// RenameFile is the rename(2) seam — tests stub it to force the
// EBUSY/EXDEV bind-mount fallback without a real mount. The write
// core (and with it the rename call) is delegated to fsx; the init
// trampoline below points fsx.RenameFile at THIS var, so RenameFile
// stays the one live seam for every WriteAtomic consumer and the
// existing stubs (hostutil_test.go, nethealth's dns_fallback EBUSY
// test) keep working unchanged.
var RenameFile = os.Rename

// The delegation hands the rename to fsx.WriteFile, whose seam is
// fsx.RenameFile — route it back through this package's var so a
// stub of RenameFile reaches the delegated core too. Init runs
// after both packages' vars are initialized, so this reliably wins
// over fsx's own os.Rename default.
func init() {
	fsx.RenameFile = func(from, to string) error { return RenameFile(from, to) }
}

// renameFallbackLogged remembers which paths already warned about the
// direct-write fallback — one line per path per process (a
// bind-mounted hosts file takes the fallback on every render and
// would spam the log).
var renameFallbackLogged sync.Map

// AtomicOpts tunes WriteAtomic — the shared staging→fsync→rename
// core behind WriteFileAtomic, promfile.Write and converge's
// Host.WriteManaged. The knobs that legitimately differ between
// consumers are the staging name shape and the page-cache hook; the
// durability contract (payload fsync before rename, dir fsync after)
// is uniform — see DirSync for the one alignment this unify forced.
// The fields map 1:1 onto fsx.Opts: the core they tune lives in
// libs/hostkit/fsx (the verbatim port of the former in-package
// implementation), hostutil keeps the API + the EBUSY/EXDEV
// bind-mount fallback above it.
type AtomicOpts struct {
	// Stage opens the staging file the rename will promote to path.
	// It must create the file in the dir it is handed (the target's
	// parent — same filesystem is what makes the rename atomic).
	// The one shape in use:
	//
	//   - StageTempPattern: CreateTemp with a "*" pattern — a
	//     private random staging name per concurrent writer (the
	//     state files workerhygiene / controllerhygiene / nethealth /
	//     hostmetrics all stamp, promfile's glob-avoidance
	//     ".<name>.*" shape, and converge's managed-file writes —
	//     a fixed staging name would let a crash-restart's two
	//     writers truncate each other's stage mid-write).
	Stage func(dir string) (*os.File, error)
	// Mode is forced onto the staging file before sync+rename —
	// CreateTemp stages 0600 and an OpenFile create-mode is
	// umask-masked, but every consumer of these files (node_exporter,
	// systemd units, hubsync renders) reads them as another user.
	Mode os.FileMode
	// DirSync fsyncs the target's parent directory after a
	// successful rename, so the directory entry itself is durable.
	// BEHAVIOR CHANGE (unification): WriteFileAtomic historically
	// skipped the dir fsync while promfile.Write/WriteManaged had
	// it — the decision aligned everyone UP to the stronger
	// contract. Without it a crash after the rename can lose the
	// file entirely (old name already unlinked, new entry not yet
	// flushed). The directory open is best-effort (a dir that
	// vanished between rename and sync must not fail an
	// already-installed write); a Sync failure IS reported — the
	// promfile.Write contract, the strictest of the three merged
	// copies (WriteManaged used to swallow it).
	DirSync bool
	// AfterSync, when set, runs after the payload fsync and before
	// Close — converge passes pagecache.Drop so a staged binary's
	// cache charge does not outlive the write (post-Sync the pages
	// are clean, so DONTNEED drops them outright).
	AfterSync func(f *os.File)
	// NoSync skips BOTH fsyncs (payload and DirSync) — the
	// CreateTemp+Chmod+Rename atomicity contract is unchanged, so
	// readers still never see a torn file; only crash durability is
	// dropped. Reserved for ephemeral files a crash may lose
	// harmlessly because the next cycle rewrites them anyway:
	// node-exporter .prom textfiles, apibe-gap-*, last-run. Config
	// files under /etc and latch/state files keep the durable
	// path — a lost latch reads as "condition cleared".
	NoSync bool
}

// StageTempPattern returns a Stage that CreateTemps a uniquely
// named staging file in dir — pattern keeps the "*" placeholder
// (CreateTemp replaces it with a random suffix).
func StageTempPattern(pattern string) func(string) (*os.File, error) {
	return fsx.StageTempPattern(pattern)
}

// WriteAtomic installs content at path via a same-dir staging file
// + rename — the one atomic-write implementation for the agent
// (promfile and converge route through it with their own
// AtomicOpts). The staging→chmod→write→fsync→rename→dirsync core is
// delegated to libs/hostkit/fsx (fsx.WriteFile — ported verbatim
// from this file, zero behavior drift); the payload fsync BEFORE
// the rename closes the crash window where the rename lands but the
// bytes were never flushed, a positive DirSync makes the rename
// itself durable, every failure path sweeps the staging file and a
// short write is a failed write — see fsx.WriteFile.
func WriteAtomic(path string, content []byte, opts AtomicOpts) error {
	return fsx.WriteFile(path, content, fsx.Opts{
		Stage:     opts.Stage,
		Mode:      opts.Mode,
		DirSync:   opts.DirSync,
		AfterSync: opts.AfterSync,
		NoSync:    opts.NoSync,
	})
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
// it (see AtomicOpts.DirSync for the durability-alignment note).
//
// rename(2) has one blind spot that matters here: the TARGET of a
// file-level bind mount cannot be renamed over — the kernel returns
// EBUSY — and that is exactly how the DaemonSet mounts
// /host/etc/hosts. EXDEV (tmp and target ever landing on different
// filesystems) shares the fallback. Both degrade to a direct
// write+fsync on the target: the crash-atomicity is lost but the
// write actually lands — strictly better than never writing at all.
func WriteFileAtomic(path, content string) error {
	err := WriteAtomic(path, []byte(content), AtomicOpts{
		Stage:   StageTempPattern(".tmp-" + filepath.Base(path) + "-*"),
		Mode:    0o644,
		DirSync: true,
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.EXDEV) {
		return err
	}
	if _, logged := renameFallbackLogged.LoadOrStore(path, true); !logged {
		logger().Warn("atomic rename refused (bind-mounted "+
			"target?) — falling back to direct fsync'd write",
			"path", path, "error", err)
	}
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
// fsyncs — same tmp+rename atomicity (AtomicOpts.NoSync), for the
// ephemeral files the next cycle rewrites anyway: .prom textfiles,
// apibe-gap-*, last-run. A crash can lose the newest content; the
// file is never torn.
func WriteFileAtomicNoSync(path, content string) error {
	err := WriteAtomic(path, []byte(content), AtomicOpts{
		Stage:  StageTempPattern(".tmp-" + filepath.Base(path) + "-*"),
		Mode:   0o644,
		NoSync: true,
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.EXDEV) {
		return err
	}
	if _, logged := renameFallbackLogged.LoadOrStore(path, true); !logged {
		logger().Warn("atomic rename refused (bind-mounted "+
			"target?) — falling back to direct fsync'd write",
			"path", path, "error", err)
	}
	return WriteFileDirect(path, content)
}

// UptimeSeconds parses the first field of a /proc/uptime-format file
// (seconds since boot, fractional part ignored by callers that cast).
func UptimeSeconds(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty uptime file %s", path)
	}
	return strconv.ParseFloat(fields[0], 64)
}

// ReadTrimmed returns the file's trimmed content, "" on any error.
func ReadTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ReadUintFile parses a file holding a single unsigned integer —
// "" ok=false on absent/unparseable content.
func ReadUintFile(path string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(
		ReadTrimmed(path)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// JSONFindInts collects EVERY numeric value of a key named in keys
// (case-insensitive) under decoded JSON — maps AND arrays are
// descended. The cilium runtime config nests its MTU differently
// across agent versions and may carry several `mtu` keys; a
// "first match" walk is nondeterministic because Go map iteration
// order is random.
func JSONFindInts(v any, out *[]int64, keys ...string) {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[strings.ToLower(k)] = true
	}
	var walk func(n any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			for k, val := range t {
				if want[strings.ToLower(k)] {
					if f, ok := val.(float64); ok {
						*out = append(*out, int64(f))
					}
				}
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
}

// ShellQuote single-quotes a shell word. The paths and configured
// names it guards are admin-controlled, but quoting keeps `sh -c`
// command strings robust against a stray space or metachar that
// would otherwise split or glob the word (hubsync's remote puts and
// kinedb's runtime-log scan both interpolate configured names into
// shell strings).
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// MTUOfIface reads <sysnet>/<iface>/mtu — the sysfs MTU of one
// interface.
func MTUOfIface(sysnet, iface string) (int64, bool) {
	data, err := os.ReadFile(filepath.Join(sysnet, iface, "mtu"))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// RuntimeConfigMTU reads the cilium MTU out of
// agent-runtime-config.json — the fallback when the datapath iface
// has no sysfs entry. With several `mtu` keys the MAX wins —
// deterministic (Go map order makes a "first match" walk unstable),
// and the drift checks want the worst-case datapath MTU anyway.
func RuntimeConfigMTU(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return 0, false
	}
	var vals []int64
	JSONFindInts(v, &vals, "mtu")
	if len(vals) == 0 {
		return 0, false
	}
	return slices.Max(vals), true
}

// TouchIfDue refreshes path's atime/mtime to now via Chtimes ONLY
// when the file's current mtime is at least minAge old — the
// callers already hold the os.Stat result, so a fresh latch costs
// zero extra syscalls (the comparison is pure arithmetic on
// fi.ModTime). Held latches used to Chtimes on every check cycle;
// with the janitor reaping at 24h a 15min cadence (latchdefs.
// LatchTouchMinInterval) is already generous. Returns the Chtimes
// error, nil when skipped or touched.
func TouchIfDue(path string, fi os.FileInfo, now time.Time, minAge time.Duration) error {
	age := now.Sub(fi.ModTime())
	// Skip only on a genuinely fresh mtime. A NEGATIVE age means the
	// file's mtime sits ahead of this clock (fake test clocks, an
	// NTP step-back) — that is exactly the case a touch must fix,
	// not skip.
	if age >= 0 && age < minAge {
		return nil
	}
	return os.Chtimes(path, now, now)
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
	// os.Stat results expose *syscall.Stat_t on Linux — the x/sys
	// unix.Stat_t is a distinct type and the assertion would always
	// fail (run_tmpfs.go:147 hit the same trap).
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("stat %s: unexpected FileInfo.Sys type %T", path, fi.Sys())
	}
	return fmt.Sprintf("%d:%d:%d:%d",
		st.Dev, st.Ino, fi.Size(), fi.ModTime().UnixNano()), nil
}
