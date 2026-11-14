// host_writes.go — the scrape-independent host sysctl writes.
//
// Two collectors self-heal host knobs: the clocksource drift
// restore (write "kvm-clock" back to current_clocksource when the
// kernel fell back to hpet/acpi_pm) and the aio-max-nr table bump
// (double the AIO ceiling past 75% use so io_setup() does not
// EAGAIN). Both used to fire INSIDE Collect — every Prometheus
// scrape and every WriteTextfile pass could stamp a sysctl write,
// and concurrent scrapes raced the same file. The writes now live
// here, driven once per Latches refresh tick (30s) under a mutex
// with a per-target retry cooldown: a persistent drift condition
// costs at most one write attempt per hostWriteRetryInterval, not
// one per scrape.
package hostmetrics

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
)

// hostWriteRetryInterval bounds how often ONE write target may be
// attempted — a failed or immediately-reverted write must not turn
// the 30s latch tick into a sysctl write storm.
const hostWriteRetryInterval = 5 * time.Minute

// writeState carries the per-Collector write bookkeeping — the
// CooldownSet's own RWMutex serializes the check-and-stamp pair
// (the latch ticker is single-goroutine today, but Collect-side
// callers and future writers share the same guard); tried is the
// per-target last-attempt stamp (success OR failure — the cooldown
// covers both so a permanently unwritable sysctl isn't retried
// every tick).
type writeState struct {
	tried ledger.CooldownSet
}

// attemptHostWrite writes content to path unless the cooldown for
// that path is still hot. Returns true when a write was attempted.
func (c *Collector) attemptHostWrite(path string, content string) bool {
	now := c.cfg.Clock.Now()
	if c.wr.tried.CooledDown(path, hostWriteRetryInterval, now) {
		return false
	}
	// Stamp BEFORE the write — unlike heal's successful-action-only
	// rule, this cooldown covers failures too (see writeState).
	c.wr.tried.Stamp(path, now)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: host write failed",
			"path", path, "error", err)
		return false
	}
	return true
}

// reconcileHostWrites runs the drift-restore + table-bump checks —
// the WRITE halves of collectClocksource/collectAIO, moved off the
// scrape path. The gauges keep reporting read-only truth in Collect;
// this pass is what actually mutates the host.
func (c *Collector) reconcileHostWrites() {
	c.maybeRestoreClocksource()
	c.maybeBumpAIOMax()
}

// maybeRestoreClocksource writes "kvm-clock" back when the active
// clocksource is a known-slow fallback AND the hardware offers
// kvm-clock — the lost-pvclock-vDSO drift shape (host
// suspend/migration). Idempotent: the write is attempted at most
// once per cooldown window.
func (c *Collector) maybeRestoreClocksource() {
	curB, err := os.ReadFile(c.cfg.ClocksourceCurrentFile)
	if err != nil {
		return
	}
	current := strings.TrimSpace(string(curB))
	if !slowClocksources[current] {
		return
	}
	availB, err := os.ReadFile(c.cfg.ClocksourceAvailableFile)
	if err != nil {
		return
	}
	available := map[string]bool{}
	for f := range strings.FieldsSeq(string(availB)) {
		available[f] = true
	}
	if !available["kvm-clock"] {
		return
	}
	if c.attemptHostWrite(c.cfg.ClocksourceCurrentFile, "kvm-clock\n") {
		logger().Warn("hostmetrics: clocksource drifted to "+current+
			" — restored kvm-clock", "path", c.cfg.ClocksourceCurrentFile)
	}
}

// maybeBumpAIOMax doubles aio-max-nr in place once the table is
// past aioUsedRatioBump — the runtime half of kernel-resource-table-tuning
// (hostconfig's convergence pass is the steady-state owner; this
// covers the gap until it runs). /proc/sys rejects atomic-rename
// writes, so it goes through a plain truncating write — the same
// semantics sysctl expects.
func (c *Collector) maybeBumpAIOMax() {
	nr, nrOK := fsx.ReadUintFile(c.cfg.aioNrFile)
	mx, mxOK := fsx.ReadUintFile(c.cfg.aioMaxFile)
	if !nrOK || !mxOK || mx == 0 || mx >= aioMaxTarget ||
		float64(nr)/float64(mx) <= aioUsedRatioBump {
		return
	}
	bumped := mx * 2
	if bumped > aioMaxTarget {
		bumped = aioMaxTarget
	}
	if c.attemptHostWrite(c.cfg.aioMaxFile, strconv.FormatUint(bumped, 10)) {
		logger().Warn("hostmetrics: aio-max-nr bumped",
			"from", mx, "to", bumped)
	}
}
