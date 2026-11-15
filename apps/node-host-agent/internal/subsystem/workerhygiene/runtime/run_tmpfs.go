// run_tmpfs.go — disk side-guard promoted out of DiskBloatCheck into
// its own wdeps.Check (wdeps.CheckRunTmpfs): per-guard WD_SIG kill
// switch, cycles{check,result} series and action labels. The
// guard body is unchanged — it always ran on the shared *wdeps.Deps.
package runtime

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type RunTmpfsCheck struct{ d *wdeps.Deps }

// NewRunTmpfs builds the runTmpfs disk guard check.
func NewRunTmpfs(d *wdeps.Deps) *RunTmpfsCheck { return &RunTmpfsCheck{d: d} }

// Name returns the check label / WD_SIG key.
func (c *RunTmpfsCheck) Name() string { return wdeps.CheckRunTmpfs }

// Run executes one runTmpfs round under its own gate.
func (c *RunTmpfsCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckRunTmpfs) {
		return
	}
	c.runTmpfsGuard(ctx)
	c.d.CycleResult(wdeps.CheckRunTmpfs, "ok")
}

// --- run-tmpfs: host /run tmpfs guard ---
//
// A full /run tmpfs kills containerd.sock, dbus and every lockfile
// on the host while every probe still answers — the classic
// "node looks healthy, nothing works" outage. The guard statfs's
// the /run mount for both bytes AND inode usage; past 80% on
// either it spends the last-run-tmpfs-clean 15m budget on a
// journal vacuum (--vacuum-size=16M on the host journal dir —
// /run/log/journal is the usual filler) plus a bounded orphan
// .tmp sweep (files older than 2h). The fill ratio itself lands
// on node_agent_run_tmpfs_used_ratio every cycle.

const (
	runTmpfsHighRatio  = 0.80
	runTmpfsCleanEvery = 15 * time.Minute
	runTmpfsMinAge     = 2 * time.Hour
	runTmpfsSweepMax   = 64 // bound one cycle's tmp sweep
)

// runTmpfsGuard executes one run-tmpfs round.
func (c *RunTmpfsCheck) runTmpfsGuard(ctx context.Context) {
	used, ok := c.d.DiskMaxUsageRatio(c.d.Cfg.Disk.HostRunDir)
	if !ok {
		return // unmeasurable — keep the last ratio, never act blind
	}
	c.d.RunTmpfsUsedRatio = used
	if used <= runTmpfsHighRatio {
		return
	}
	if !c.d.State.RateTrySpend("last-run-tmpfs-clean", runTmpfsCleanEvery) {
		return
	}
	cleaned := false
	// (1) journald vacuum — the usual filler. Exec runs
	// nsenter-wrapped to the host namespaces, so JournalVacuumDir
	// is the HOST view (/run/log/journal), not the container's
	// /host/ path.
	if sd := c.d.Cfg.Systemd; sd != nil {
		if _, err := sd.Exec(ctx, "journalctl",
			"--directory="+c.d.Cfg.Disk.JournalVacuumDir,
			"--vacuum-size=16M"); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: run-tmpfs journal vacuum %s failed: %v",
				c.d.Cfg.Disk.JournalVacuumDir, err))
		} else {
			cleaned = true
		}
	}
	// (2) orphan .tmp sweep — files older than 2h under /run.
	// Bounded: at most runTmpfsSweepMax removals per cycle. An
	// fd-held file is skipped (runTmpfsFDHeld against the sweep's
	// single /proc/*/fd pass): unlinking it would
	// orphan the writer's inode — no space regained, data lost at
	// close (incident parity with unlinked-open-files).
	now := c.d.Cfg.Seams.Host.Clock.Now()
	removed := 0
	// Mount boundary: /run holds bind-mounted container rootfs trees
	// (containerd's <id>/rootfs under /run/k0s/...) — a stale .tmp
	// name inside a USER POD's rootfs must never be unlinked by the
	// host sweep. find -xdev semantics: any directory whose st_dev
	// differs from the walk root's is a different filesystem —
	// SkipDir prunes it (and everything beneath) outright.
	rootDir := c.d.Cfg.Disk.HostRunDir
	rootDev, rootDevOK := uint64(0), false
	if rootSt, serr := os.Stat(rootDir); serr == nil {
		if rst, ok := rootSt.Sys().(*syscall.Stat_t); ok {
			rootDev, rootDevOK = rst.Dev, true
		}
	}
	// The /proc/*/fd pass is built ONCE per sweep, lazily on the
	// first stale .tmp — a busy /run can hold dozens of candidates
	// and the old per-file rescan cost O(candidates × fds) stats.
	// openFDsDone separates "not built yet" from "built, possibly
	// empty/nil" so a failed pass doesn't rescan per file.
	// openFDsOK=false means the pass could not prove what is held
	// open — the sweep then fails CLOSED and removes nothing this
	// cycle (deleting blind could unlink a live spool file).
	var openFDs map[fdID]struct{}
	openFDsDone, openFDsOK := false, true
	_ = filepath.WalkDir(rootDir,
		func(path string, de fs.DirEntry, err error) error {
			if err != nil || removed >= runTmpfsSweepMax {
				return nil //nolint:nilerr // unreadable entries are skipped, never fatal
			}
			if de.IsDir() && path != rootDir {
				dfi, derr := de.Info()
				if derr != nil {
					return filepath.SkipDir
				}
				if runTmpfsForeignDev(dfi, rootDev, rootDevOK) {
					return filepath.SkipDir
				}
				return nil
			}
			if !de.Type().IsRegular() ||
				!strings.HasSuffix(de.Name(), ".tmp") {
				return nil
			}
			fi, ierr := de.Info()
			if ierr != nil || now.Sub(fi.ModTime()) < runTmpfsMinAge {
				return nil //nolint:nilerr // stat failures skip the entry, never fatal
			}
			if !openFDsDone {
				openFDs, openFDsOK = c.runTmpfsOpenFDs()
				openFDsDone = true
			}
			if !openFDsOK {
				// The fd census failed — nothing can be proven an
				// orphan. Abort the sweep rather than delete blind.
				return fs.SkipAll
			}
			if runTmpfsFDHeld(fi, openFDs) {
				// SKIP open-fd — removing an fd-held spool file
				// unlinks the name but not the inode: the writer
				// keeps filling an orphan inode (no space regained)
				// and its data vanishes at close, exactly during
				// the ≥80% emergency this sweep serves.
				c.d.State.AppendLog(fmt.Sprintf(
					"SKIP open-fd %s — held open, not an orphan; sweep left it alone",
					path))
				return nil
			}
			if rerr := os.Remove(path); rerr == nil {
				removed++
				cleaned = true
			}
			return nil
		})
	if cleaned {
		c.d.RunTmpfsCleanups++
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: run-tmpfs-clean — /run at %.0f%%, journal vacuumed to 16M, %d orphan .tmp removed",
			used*100, removed))
		c.d.Actions.WithLabelValues(wdeps.CheckRunTmpfs, "run_tmpfs_clean").Inc()
	}
}

// fdID is the (dev,ino) identity of an open file — the same
// comparison the old per-candidate probe did, now computed once per
// sweep for the whole /proc/*/fd pass.
type fdID struct {
	dev uint64
	ino uint64
}

// runTmpfsOpenFDs builds the set of (dev,ino) pairs held open by
// ANY process — ONE pass over /proc/<pid>/fd/<n> per sweep instead
// of one per stale .tmp candidate. os.Stat follows each fd's magic
// link to the OPEN file's inode, so no Readlink+Stat(target) pair
// per fd and no path-prefix compare that hardlinks/renames would
// defeat: the (dev,ino) set is the identity. Unreadable /proc/<pid>
// entries are skipped: a process dying mid-scan is normal. The bool
// reports whether the census actually ran — ok=false (proc root
// unreadable) means the sweep must fail CLOSED and remove nothing:
// the old nil-map fail-open deleted .tmp files it could not prove
// were orphaned.
func (c *RunTmpfsCheck) runTmpfsOpenFDs() (map[fdID]struct{}, bool) {
	pids, err := c.d.Proc.PIDs()
	if err != nil {
		return nil, false
	}
	set := make(map[fdID]struct{})
	readOK := 0
	for _, pid := range pids {
		fdDir := c.d.Proc.File(pid, "fd")
		fds, rerr := os.ReadDir(fdDir)
		if rerr != nil {
			continue // raced exit — normal, never fatal
		}
		readOK++
		for _, fd := range fds {
			// Stat the fd PATH, not its readlink target: the magic
			// link resolves to the file the fd actually holds —
			// including unlinked names whose target path no longer
			// exists (the exact case this guard exists for).
			tfi, serr := os.Stat(filepath.Join(fdDir, fd.Name()))
			if serr != nil {
				continue
			}
			if tst, tok := tfi.Sys().(*syscall.Stat_t); tok { // os stat results expose syscall.Stat_t, not unix.Stat_t
				set[fdID{dev: tst.Dev, ino: tst.Ino}] = struct{}{}
			}
		}
	}
	// Every fd dir unreadable (hidepid=2, EACCES storm) yields an
	// EMPTY set that would read as "no process holds anything" —
	// the sweep would then delete every .tmp as orphaned. A census
	// that read nothing proves nothing: fail closed.
	if len(pids) > 0 && readOK == 0 {
		return nil, false
	}
	return set, true
}

// runTmpfsForeignDev reports whether a walked directory sits on a
// different filesystem than the walk root (find -xdev semantics).
// An unknown root dev or an uncomparable stat both answer false —
// the sweep then behaves exactly like the pre-boundary walk.
func runTmpfsForeignDev(fi os.FileInfo, rootDev uint64, rootDevOK bool) bool {
	if !rootDevOK {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t) // os stat results expose syscall.Stat_t, not unix.Stat_t
	if !ok {
		return false
	}
	return st.Dev != rootDev
}

// runTmpfsFDHeld reports whether the candidate file's (dev,ino) is
// in the sweep's open-fd set — an uncomparable stat fails open like
// the old probe (the caller only reaches here with a built set).
func runTmpfsFDHeld(fi os.FileInfo, open map[fdID]struct{}) bool {
	cst, ok := fi.Sys().(*syscall.Stat_t) // os stat results expose syscall.Stat_t, not unix.Stat_t
	if !ok {
		return false // uncomparable — fail open like the old sweep
	}
	_, held := open[fdID{dev: cst.Dev, ino: cst.Ino}]
	return held
}
