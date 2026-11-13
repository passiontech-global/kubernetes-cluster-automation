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
	"errors"
	"os"
	"strconv"
	"strings"
)

// binaryNewerThanService reports whether the managed binary at
// hostPath was written AFTER unit's current active incarnation
// started — the running daemon predates the on-disk binary, so only
// a restart picks it up (SIGHUP reloads config inside the old
// image). Both sides resolve to unix epoch seconds: the binary's
// mtime vs ActiveEnterTimestampMonotonic anchored by /proc/stat
// btime — the formatted ActiveEnterTimestamp is unusable (its zone
// abbrev misparses off-UTC; platform/systemd documents the same
// trap for ActiveAge). Every probe failure answers false: "can't
// prove skew" must never flap the unit.
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
	if err != nil || monoUS <= 0 {
		// 0/"n/a"/empty = never activated this boot — nothing to
		// compare against (an inactive unit execs the on-disk
		// binary on its next start anyway).
		return false
	}
	btime, err := procBootEpoch()
	if err != nil {
		return false
	}
	activeSince := btime + monoUS/1_000_000
	return fi.ModTime().Unix() > activeSince
}

// procBootEpoch returns /proc/stat btime — the realtime epoch the
// monotonic clock (ActiveEnterTimestampMonotonic, /proc/uptime)
// counts from. btime is a system property, not PID-namespaced, so
// the container's /proc/stat reports the host's boot time in both
// pod (hostPID) and standalone mode.
func procBootEpoch() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		}
	}
	return 0, errors.New("/proc/stat: btime not found")
}
