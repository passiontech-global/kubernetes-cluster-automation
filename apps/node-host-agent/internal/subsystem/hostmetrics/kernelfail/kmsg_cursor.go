// kmsg_cursor.go — kernel-dmesg: the persisted resume position
// (kmsg-cursor file) — its shape, the parse and write, and the
// boot_id read that separates a same-boot resume from a post-reboot
// one. Pure move out of kmsg.go (per-concern file split).
package kernelfail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// kmsgCursorFile is the resume-cursor file inside the watchdog
// state dir — marker/state file names there are shared with
// workerhygiene (the SystemOOMVictim consumer) by convention.
const kmsgCursorFile = "kmsg-cursor"

// kmsgCursor is the persisted resume position — one line in
// kmsg-cursor:
//
//	kmsg <bootid> <seq> <usec>        — /dev/kmsg mode
//	dmesgT <unixTs> <consumedAtTs>    — dmesg -T fallback
//	dmesgRaw <lineCount> <lineHash>   — plain dmesg last resort
//
// bootid+usec detect a reboot the seq counter can't (kmsg seqs
// restart at a low value every boot). dmesgT's second field counts
// same-second records already consumed (dmesg -T has 1s
// granularity); dmesgRaw's hash anchors on the last processed line
// because a saturated ring holds a CONSTANT line count — a pure
// count cursor would go permanently blind.
type kmsgCursor struct {
	mode   string
	bootID string
	seq    uint64
	usec   int64
	unixTS int64
	lines  int
	hash   uint64
}

// kernelBootID reads /proc/sys/kernel/random/boot_id under ProcRoot.
func (r *Runner) kernelBootID() string {
	b, err := os.ReadFile(filepath.Join(r.deps.ProcRoot,
		"sys/kernel/random/boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (r *Runner) readKmsgCursor() *kmsgCursor {
	b, err := os.ReadFile(r.statePath(kmsgCursorFile))
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return nil
	}
	cur := &kmsgCursor{mode: f[0]}
	switch cur.mode {
	case "kmsg":
		if len(f) < 4 {
			return nil
		}
		cur.bootID = f[1]
		cur.seq, _ = strconv.ParseUint(f[2], 10, 64)
		cur.usec, _ = strconv.ParseInt(f[3], 10, 64)
	case "dmesgT":
		if len(f) < 2 {
			return nil
		}
		cur.unixTS, _ = strconv.ParseInt(f[1], 10, 64)
		if len(f) >= 3 {
			cur.lines, _ = strconv.Atoi(f[2])
		} else {
			// Legacy "dmesgT <ts>" cursor — the same-second
			// consumed count is unknowable; -1 makes drainDmesg
			// skip ALL same-second lines rather than risk a
			// one-time double count.
			cur.lines = -1
		}
	case "dmesgRaw":
		if len(f) < 2 {
			return nil
		}
		cur.lines, _ = strconv.Atoi(f[1])
		if len(f) >= 3 {
			cur.hash, _ = strconv.ParseUint(f[2], 10, 64)
		}
	default:
		return nil
	}
	return cur
}

func (r *Runner) writeKmsgCursor(cur *kmsgCursor) {
	var content string
	switch cur.mode {
	case "kmsg":
		content = fmt.Sprintf("kmsg %s %d %d\n", cur.bootID, cur.seq, cur.usec)
	case "dmesgT":
		content = fmt.Sprintf("dmesgT %d %d\n", cur.unixTS, cur.lines)
	case "dmesgRaw":
		content = fmt.Sprintf("dmesgRaw %d %d\n", cur.lines, cur.hash)
	}
	p := r.statePath(kmsgCursorFile)
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Debug("hostmetrics: kmsg cursor write failed",
			"path", p, "error", err)
	}
}
