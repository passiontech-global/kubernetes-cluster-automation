// binary_skew.go — the "on-disk binary newer than the running
// daemon" probe shared by the managed-binary groups (nebula,
// coredns). installManagedBinary's onInstalled only sees THIS
// cycle's untar; skew left behind by earlier converge paths —
// pre-onInstalled agents that installed a new nebula without
// restarting the unit, staged-tarball installs, manual swaps — is
// invisible to it. Comparing the binary mtime against the unit's
// active-since catches every path that leaves a stale daemon.
package hostconfig

import (
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// binaryNewerThanService reports whether the managed binary at
// hostPath was written AFTER unit's current active incarnation
// started — the running daemon predates the on-disk binary, so only
// a restart picks it up (SIGHUP reloads config inside the old
// image). Both sides resolve in CLOCK_MONOTONIC: ActiveEnterTimestampMonotonic
// counts on CLOCK_MONOTONIC (which pauses across VM suspend/live-migration,
// unlike /proc/stat btime's CLOCK_BOOTTIME origin), so computing
// activeSince as Clock.Now().Add(-(nowMono - monoDur)) avoids false-positive
// restarts after suspend/resume. Every probe failure answers false:
// "can't prove skew" must never flap the unit.
func (c *cyc) binaryNewerThanService(hostPath, unit string) bool {
	fi, err := os.Stat(c.r.hp(hostPath))
	if err != nil {
		return false
	}
	out, err := c.r.run(c.ctx, "systemctl", "show", "-p",
		"ActiveEnterTimestampMonotonic", "--value", unit)
	if err != nil {
		return false
	}
	monoUS, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil || monoUS <= 0 || monoUS > math.MaxInt64/int64(time.Microsecond) {
		// 0/"n/a"/empty = never activated this boot — nothing to
		// compare against (an inactive unit execs the on-disk
		// binary on its next start anyway).
		return false
	}
	monoDur := time.Duration(monoUS) * time.Microsecond
	monoFn := c.monoNow
	if monoFn == nil {
		monoFn = defaultMonoNow
	}
	nowMono, err := monoFn()
	if err != nil || monoDur > nowMono {
		return false
	}
	activeSince := c.r.cfg.Clock.Now().Add(-(nowMono - monoDur))
	return fi.ModTime().Unix() > activeSince.Unix()
}

func defaultMonoNow() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond, nil
}
