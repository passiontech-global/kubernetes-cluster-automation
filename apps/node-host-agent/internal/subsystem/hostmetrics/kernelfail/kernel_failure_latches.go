// kernel_failure_latches.go — shared kernel deep-failure latch
// contract: the cross-domain constants and the state-dir latch
// helpers the domain files (kmsg.go, pidfd.go, clockskew.go,
// fsreadonly.go, steal_entropy.go) share. The package-level
// contract overview lives in kernelfail.go; the ticker entry
// (Refresh) it feeds stays in the parent's latches.go.
package kernelfail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// --- shared kernel-failure helpers ---

// kmsgFsErrorFile is the cross-domain evidence marker: kmsg.go's
// noteKernelFsError writes it and fsreadonly.go's
// updateFSReadonlyEvidence consumes it. Marker/state file names live
// inside the watchdog state dir — shared with workerhygiene (the
// SystemOOMVictim consumer) by convention.
const kmsgFsErrorFile = "kmsg-fs-error"

func (r *Runner) statePath(name string) string {
	return filepath.Join(r.deps.StateDir, name)
}

// ensureStateLatch installs a state latch when absent (epoch
// content, written through the Store's atomic WriteEpochFile —
// concurrent ticker/scrape writers share no fixed .tmp-<name>
// staging file) and logs the transition once. An EXISTING latch gets
// its mtime refreshed (BUG-H6) — the kmsg signatures recur for as
// long as the kernel condition does, and the janitor's 24h reap keys
// on mtime, so a live episode must not age out between the refresh
// loop's touches.
func (r *Runner) ensureStateLatch(path, name, evidence string) {
	if fi, err := os.Stat(path); err == nil {
		// Touch only once the mtime ages past LatchTouchMinInterval —
		// the janitor reaps at 24h, so a per-tick utimensat was
		// ~2,800 needless syscalls/day per held latch.
		if cerr := hostutil.TouchIfDue(path, fi, r.deps.Clock.Now(),
			latchdefs.LatchTouchMinInterval); cerr != nil {
			logger().Debug("hostmetrics: latch touch failed",
				"path", path, "error", cerr)
		}
		return
	}
	if !r.deps.Store.WriteEpochFile(path, r.deps.Clock.Now().Unix()) {
		return
	}
	logger().Warn("hostmetrics: "+name+" latch set — "+evidence,
		"path", path)
	// A NEW latch also lands a STATE-ENTER line in the shared
	// watchdog log — nodereporter's events.go tails that file and
	// maps "STATE-ENTER: <name>" onto a Kubernetes Event. The name
	// argument here is the display form ("state-<latch>"); the log
	// line carries the bare latch suffix the event regexes anchor
	// on. The line goes through the Store's AppendLog — NOT a bare
	// logger() call — because the file half is the contract, not
	// the slog mirror.
	r.deps.Store.AppendLog(fmt.Sprintf(latchdefs.StateEnterPrefix+"%s (%s)",
		strings.TrimPrefix(name, latchdefs.LatchFilePrefix), evidence))
}

// --- small shared helpers (uniquely named per file rules) ---
//
// The last-* rate budgets (conntrackBumpBudgetFile,
// clockStepBudgetFile) go through r.deps.Store — the shared
// hoststate rateOK/rateSpend parity (atomic spend, same file
// format).
