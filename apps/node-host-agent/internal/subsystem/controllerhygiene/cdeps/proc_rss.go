// proc_rss.go — /proc/<pid>/status VmRSS reader over Deps.Proc.
// Shared by konnectivity-server and kine RSS leak guards so both read
// directly from the existing procfs view (no derived seam).
package cdeps

import (
	"os"
	"strconv"
	"strings"
)

// ProcVMRSS reads VmRSS bytes from /proc/<pid>/status ("VmRSS: <n> kB")
// via d.Proc. Returns (0, false) when pid <= 0, the file is unreadable,
// or VmRSS is absent/malformed.
func (d *Deps) ProcVMRSS(pid int) (uint64, bool) {
	if pid <= 0 {
		return 0, false
	}
	data, err := os.ReadFile(d.Proc.File(pid, "status"))
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line) // "VmRSS:" "<n>" "kB"
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb << 10, true
	}
	return 0, false
}
