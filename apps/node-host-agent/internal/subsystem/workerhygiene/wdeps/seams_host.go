// seams_host — the Host host-primitive group of the Seams test-seam surface, split out of
// seams.go (which keeps the Seams aggregate + applyDefaults
// orchestration).
package wdeps

import (
	"context"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Host holds the host-primitive seams — the calls that touch the
// host itself rather than a remote endpoint: signal delivery, the
// clock, fs usage, CPU/IO scheduling drops, the journald reads and
// the deleted-fd stat.
type Host struct {
	// KillFn delivers signals — seam for tests (SIGKILL on pause /
	// proxy-agent/shim/cilium pids, and signal-0 liveness probes).
	KillFn func(pid int, sig syscall.Signal) error
	// Clock supplies the current time — the shared timex.Cell seam.
	Clock *timex.Cell
	// JournalFn returns the k0sworker journal window — the runner's
	// shared -10min snapshot (05/06). nil → Systemd.Journal.
	JournalFn func(ctx context.Context) (string, error)
	// JournalAnyFn is the A5 second probe — `journalctl -n 1
	// --no-pager` with NO unit filter. An empty k0sworker window is
	// only corruption evidence when journald ITSELF has nothing (or
	// only corrupt warnings) to say — a quiet unit on a healthy
	// journald must not trigger the rotate+vacuum remedy. nil →
	// Systemd.ExecCombined (stderr folded in — journald's own
	// diagnostics, e.g. "File ... is corrupt", never reach stdout).
	JournalAnyFn func(ctx context.Context) (string, error)
	// StatfsFn reads fs usage for the ingest-GC disk trigger (A3).
	// Seam for tests (default unix.Statfs).
	StatfsFn func(string, *unix.Statfs_t) error
	// StatFn stats one host path — the spegel stale-containerd-sock
	// staleness read (/run/k0s/containerd.sock lives on the HOST, a
	// path tests cannot create). Default os.Stat; tests point it at
	// a temp file. Seam.
	StatFn func(path string) (os.FileInfo, error)
	// ReniceFn drops one pid to the lowest CPU scheduling priority
	// (renice +19) — the io-pressure throttler's CPU half. Default
	// syscall.Setpriority; tests record instead of renicing.
	ReniceFn func(pid int) error
	// IoniceIdleFn puts one pid in the idle I/O scheduling class
	// (ionice -c 3) — the io-pressure throttler's I/O half. Default
	// the ioprio_set syscall (ionice_other.go reports unsupported
	// off-Linux). Seam.
	IoniceIdleFn func(pid int) error
	// DeletedFDStatFn stats a /proc/<pid>/fd link whose readlink
	// target ends in " (deleted)" — the kernel resolves the magic
	// link to the still-open inode, so the fd's dev/ino/size are
	// readable even though the path is gone (the
	// unlinked-open-files guard's evidence source and (dev,ino)
	// dedup key). ok=false when the fd vanished mid-walk or isn't
	// a regular file. Seam.
	DeletedFDStatFn func(path string) (dev, ino uint64, size int64, ok bool)
	// LinkDelFn deletes one host-netns interface by name — the
	// calico orphan-veth GC's `ip link delete` replacement
	// (netlinkx.LinkDel on pid 1, the host init — same target the
	// old systemd Exec ran in). Default the netlink call; tests
	// record instead of touching real links.
	LinkDelFn func(name string) error
}

func (s *Host) applyDefaults(c *Config) {
	if s.KillFn == nil {
		s.KillFn = func(pid int, sig syscall.Signal) error {
			return syscall.Kill(pid, sig)
		}
	}
	if s.Clock == nil {
		if c.Base.Clock != nil {
			s.Clock = c.Base.Clock
		} else {
			s.Clock = timex.NewCell(nil)
		}
	}
	if c.Base.Clock == nil {
		c.Base.Clock = s.Clock
	}
	if s.JournalFn == nil {
		sd := c.Systemd
		s.JournalFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				// Fail, not empty: a nil client fed the unreadable
				// tracker a fake "journald-wide empty reply" verdict.
				return "", errors.New("no systemd client wired")
			}
			return sd.Journal(ctx, "k0sworker.service", journalWindow)
		}
	}
	if s.JournalAnyFn == nil {
		sd := c.Systemd
		s.JournalAnyFn = func(ctx context.Context) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.ExecCombined(ctx,
				"journalctl", "-n", "1", "--no-pager")
		}
	}
	if s.StatfsFn == nil {
		s.StatfsFn = unix.Statfs
	}
	if s.StatFn == nil {
		s.StatFn = os.Stat
	}
	if s.ReniceFn == nil {
		s.ReniceFn = func(pid int) error {
			return syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
		}
	}
	if s.IoniceIdleFn == nil {
		s.IoniceIdleFn = ioniceIdle // build-tag split: linux ioprio_set
	}
	if s.DeletedFDStatFn == nil {
		s.DeletedFDStatFn = deletedFDStat
	}
	if s.LinkDelFn == nil {
		s.LinkDelFn = func(name string) error {
			return netlinkx.LinkDel(1, name)
		}
	}
}

// applyDefaults fills the Ctr group's production implementation —
// the one exec seam: a full-argv passthrough onto Systemd.Exec,
// nil-safe the same way the three per-command defaults were (the
// named methods carry the argv each old default hardcoded).
