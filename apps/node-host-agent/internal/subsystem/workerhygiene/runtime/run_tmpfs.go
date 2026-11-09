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

	"golang.org/x/sys/unix"

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
	var st unix.Statfs_t
	if err := c.d.Cfg.Seams.Host.StatfsFn(c.d.Cfg.Disk.HostRunDir, &st); err != nil ||
		st.Blocks == 0 {
		return // unmeasurable — keep the last ratio, never act blind
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	if st.Files > 0 && st.Ffree <= st.Files {
		if iu := 1.0 - float64(st.Ffree)/float64(st.Files); iu > used {
			used = iu
		}
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
	// fd-held file is skipped (runTmpfsFDOpen): unlinking it would
	// orphan the writer's inode — no space regained, data lost at
	// close (incident parity with unlinked-open-files).
	now := c.d.Cfg.Seams.Host.Clock.Now()
	removed := 0
	_ = filepath.WalkDir(c.d.Cfg.Disk.HostRunDir,
		func(path string, de fs.DirEntry, err error) error {
			if err != nil || removed >= runTmpfsSweepMax {
				return nil //nolint:nilerr // unreadable entries are skipped, never fatal
			}
			if !de.Type().IsRegular() ||
				!strings.HasSuffix(de.Name(), ".tmp") {
				return nil
			}
			fi, ierr := de.Info()
			if ierr != nil || now.Sub(fi.ModTime()) < runTmpfsMinAge {
				return nil //nolint:nilerr // stat failures skip the entry, never fatal
			}
			if c.runTmpfsFDOpen(path, fi) {
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

// runTmpfsFDOpen reports whether any process holds an open fd on
// the candidate file. The /proc fd walk runs only once a sweep
// candidate exists (never on an empty walk) and compares
// readlink targets under HostRunDir by Dev+Inode — the path check
// alone would miss hardlinks/renames. Unreadable /proc/<pid>
// entries are skipped: a process dying mid-scan is normal.
func (c *RunTmpfsCheck) runTmpfsFDOpen(path string, fi os.FileInfo) bool {
	cst, ok := fi.Sys().(*syscall.Stat_t) // os stat results expose syscall.Stat_t, not unix.Stat_t
	if !ok {
		return false // uncomparable — fail open like the old sweep
	}
	pids, err := c.d.Proc.PIDs()
	if err != nil {
		return false
	}
	runPrefix := c.d.Cfg.Disk.HostRunDir + "/"
	for _, pid := range pids {
		fdDir := c.d.Proc.File(pid, "fd")
		fds, rerr := os.ReadDir(fdDir)
		if rerr != nil {
			continue // raced exit — normal, never fatal
		}
		for _, fd := range fds {
			target, lerr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if lerr != nil || !strings.HasPrefix(target, runPrefix) {
				continue
			}
			tfi, serr := os.Stat(target)
			if serr != nil {
				continue
			}
			if tst, tok := tfi.Sys().(*syscall.Stat_t); tok &&
				tst.Dev == cst.Dev && tst.Ino == cst.Ino {
				return true
			}
		}
	}
	return false
}
