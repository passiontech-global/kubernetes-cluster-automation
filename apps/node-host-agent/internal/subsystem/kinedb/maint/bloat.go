// bloat.go — the post-storm index-bloat emergency (roadmap B7,
// incident 2026-09-28 class): DELETE+VACUUM reclaims dead tuples but
// never shrinks the B-Tree — after a revision storm the kine indexes
// stay at many times the heap size, and every MAX(id)/LIST pays the
// bloat until the NEXT daily maint window reindexes. This is the
// out-of-band path: when pg_indexes_size > 3x the heap AND > 1GiB,
// run REINDEX TABLE CONCURRENTLY TODAY under the compact guard's
// advisory lock (buildHeavyScript parity — one locked psql session)
// instead of waiting for the epoch-gated heavy block, with a
// last-urgent-reindex epoch file (the last-maint-run contract) so a
// bloat that reindexes away cannot replay next cycle and a failed
// reindex retries on the next maint tick.
//
// The gate runs on EVERY maint cycle — heavy or skipped: the
// cheap-stats path keeps the gauges fresh precisely so this verdict
// can fire mid-interval (a db-vm agent restart after a storm is
// enough to trigger it same-day).
package maint

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

const (
	// indexHeapBloatRatio / indexBloatMinBytes — the roadmap B7
	// thresholds: indexes > 3x the live heap AND > 1GiB. The
	// absolute floor matters (a near-empty table triples trivially —
	// the same ratio-alone false positive deadTupleRatioMax guards).
	indexHeapBloatRatio = 3
	indexBloatMinBytes  = 1 << 30

	// urgentReindexFile is the cooldown epoch under GuardStateDir —
	// the last-*-file contract (last-maint-run parity): one
	// out-of-band reindex per maint interval, so the urgent path
	// cannot itself become the storm it was built to drain.
	urgentReindexFile = "last-urgent-reindex"

	// urgentReindexCooldown is the same cadence the daily heavy
	// block uses: a bloat reindexed today that regrows past the
	// gate again tomorrow is a REAL recurrence, and the daily
	// window would have reindexed anyway.
	urgentReindexCooldown = kdeps.DefaultMaintInterval
)

// indexBloatExcessive is the urgent-reindex gate — idx > 3x heap
// AND > 1GiB.
func indexBloatExcessive(heap, idx int64) bool {
	return idx > indexHeapBloatRatio*heap && idx > indexBloatMinBytes
}

// urgentReindex evaluates the post-storm gate and, when it trips,
// reindexes out-of-band under the compact guard's advisory lock.
// res.urgentState reads off|cooldown|skipped-lock-busy|done|fail —
// off/cooldown/skipped-lock-busy count as ok (skip-counts-as-ok
// parity with the repack gates), only a RAN-AND-FAILED reindex
// flips okUrgent.
func (m *Maint) urgentReindex(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {
	res.urgentState = "off"
	if m.d.Cfg.ReadOnly {
		// check-kine-db CLI contract: no actions, no state writes
		// (stampMaintEpoch parity).
		return
	}
	if !indexBloatExcessive(res.heapBytes, res.indexBytes) {
		return
	}
	note(fmt.Sprintf("urgent-reindex gate: idx=%dB > 3x heap=%dB and > 1GiB "+
		"(post-storm bloat — out-of-band REINDEX)", res.indexBytes, res.heapBytes))
	logger().Warn("kinedb: kine index bloat past the urgent gate — "+
		"out-of-band REINDEX TABLE CONCURRENTLY",
		"heap", res.heapBytes, "indexes", res.indexBytes)
	epochPath := filepath.Join(m.d.Cfg.GuardStateDir, urgentReindexFile)
	if epoch, err := kdeps.ReadIntFile(epochPath); err == nil &&
		m.d.Cfg.Clock.Now().Sub(time.Unix(epoch, 0)) < urgentReindexCooldown {
		res.urgentState = "cooldown"
		note("urgent reindex skipped: last-urgent-reindex inside the cooldown")
		return
	}
	// The locked REINDEX reuses the heavy script's single-session
	// shape (try-lock → REINDEX TABLE CONCURRENTLY → unlock); a busy
	// lock skips WITHOUT stamping the cooldown — the compact ends in
	// VACUUM anyway and the bloat persists (heavy-block parity).
	if pout, perr := m.d.PsqlScript(ctx, pg, user, pass, m.buildLockProbe()); perr != nil {
		note(fmt.Sprintf("urgent-reindex-lock-probe-fail: %v", perr))
		res.urgentState = "skipped-lock-busy"
		return
	} else if strings.Contains(pout, kdeps.LockBusyMarker) {
		res.urgentState = "skipped-lock-busy"
		note("urgent reindex skipped: compact-guard advisory lock busy")
		logger().Warn("kinedb: urgent reindex skipped — compact-guard advisory lock busy")
		return
	}
	t0 := m.d.Cfg.Clock.Now()
	sout, serr := m.d.PsqlScript(ctx, pg, user, pass,
		m.buildHeavyScript(false))
	if serr != nil {
		if m.d.LongBudgetExceeded(t0, serr) {
			m.reapOrphanedMaint(ctx, pg, user, pass, note)
		}
		res.urgentState = "fail"
		res.okUrgent = false
		note(fmt.Sprintf("urgent-reindex-fail: %v", serr))
		return
	}
	// The locked script exits 0 even when the try-lock lost — it
	// echoes LockBusyMarker and skips the REINDEX. Stamping the
	// cooldown on that path would park the bloat for 24h without
	// ever reindexing (the heavy-block parity the lock probe
	// exists for).
	if strings.Contains(sout, kdeps.LockBusyMarker) {
		res.urgentState = "skipped-lock-busy"
		note("urgent reindex skipped: compact-guard advisory lock busy")
		return
	}
	// Stamp the cooldown only on a completed reindex — a failed one
	// retries on the next maint tick.
	kdeps.WriteIntFile(epochPath, m.d.Cfg.Clock.Now().Unix())
	res.urgentState = "done"
	note(fmt.Sprintf("urgent reindex done (idx was %dB, heap %dB)",
		res.indexBytes, res.heapBytes))
}
