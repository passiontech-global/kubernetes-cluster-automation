// Package compact ports kine-compact-guard.sh — the 10-minute
// emergency compactor for the kine DB VM.
//
// Why it exists: kine's poll catch-up streams every row since
// compact_rev into heap on boot. When compaction stalls (OOM loop,
// dead compactor — incidents 2026-10-02, 2026-10-09) the kine table
// balloons and controllers OOM-fill on every restart. This guard
// replays kine's own compact semantics in bounded chunks when the
// debt crosses the thresholds, or when compact_rev stays frozen
// while head keeps advancing.
//
// Trigger (task spec):
//
//	retained > 150000  OR  rows > 400000  OR
//	(freeze_cycles >= 4 AND head > last_head + 100 AND retained > 1000)
//
// The run executes in ONE psql session that first takes
// pg_try_advisory_lock(20260921), then replays UpdateCompactSQL +
// CompactSQL per 150K-revision chunk (max 20), VACUUM (ANALYZE)s and
// releases the lock. A second guard — on this host or anywhere else
// with DB access — sees the lock taken and skips.
//
// State under GuardStateDir: last-head, last-compact-rev,
// freeze-cycles, last-compact-ts. The backup-health physical-backup
// verifier rides the same cycle (backup.go). The probe and maint
// loops live in sibling packages; everything shared goes through
// kdeps.Deps.
package compact

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// Guard state file names under GuardStateDir.
const (
	guardFileLastHead       = "last-head"
	guardFileLastCompactRev = "last-compact-rev"
	guardFileFreeze         = "freeze-cycles"
	guardFileCompactTS      = "last-compact-ts"
)

// reDeleted matches the `deleted=N` notices the compact script's
// chunk DO blocks SELECT back.
var reDeleted = regexp.MustCompile(`deleted=([0-9]+)`)

// Guard runs the 10-minute emergency compactor — the
// kine-compact-guard.sh port plus the backup verifier that shares
// its cadence. It keeps no state of its own: config, metrics and
// the exec plumbing live on the shared *kdeps.Deps.
type Guard struct {
	d *kdeps.Deps
}

// New returns the compact-guard loop over d.
func New(d *kdeps.Deps) *Guard { return &Guard{d: d} }

// guardState is the cross-run history read from GuardStateDir.
type guardState struct {
	head       int64
	compactRev int64
	freeze     int64
	seen       bool // false when the state files are absent/unreadable
}

func (g *Guard) readGuardState() guardState {
	dir := g.d.Cfg.GuardStateDir
	head, errH := kdeps.ReadIntFile(filepath.Join(dir, guardFileLastHead))
	crev, errC := kdeps.ReadIntFile(filepath.Join(dir, guardFileLastCompactRev))
	fz, _ := kdeps.ReadIntFile(filepath.Join(dir, guardFileFreeze))
	return guardState{head: head, compactRev: crev, freeze: fz,
		seen: errH == nil && errC == nil}
}

func (g *Guard) writeGuardState(head, compactRev, freeze int64) {
	dir := g.d.Cfg.GuardStateDir
	kdeps.WriteIntFile(filepath.Join(dir, guardFileLastHead), head)
	kdeps.WriteIntFile(filepath.Join(dir, guardFileLastCompactRev), compactRev)
	kdeps.WriteIntFile(filepath.Join(dir, guardFileFreeze), freeze)
}

func (g *Guard) readGuardCompactTS() int64 {
	v, _ := kdeps.ReadIntFile(filepath.Join(g.d.Cfg.GuardStateDir, guardFileCompactTS))
	return v
}

func (g *Guard) writeGuardCompactTS(ts int64) {
	kdeps.WriteIntFile(filepath.Join(g.d.Cfg.GuardStateDir, guardFileCompactTS), ts)
}

// guardTrigger is the pure trigger predicate — separated for tests.
func (g *Guard) guardTrigger(head, compactRev, rows, retained, freeze int64, prev guardState) (bool, string) {
	switch {
	case retained > g.d.Cfg.RetainedMax:
		return true, "retained-debt"
	case rows > g.d.Cfg.RowsMax:
		return true, "rows-debt"
	case prev.seen && freeze >= g.d.Cfg.FrozenCycles &&
		head > prev.head+g.d.Cfg.FrozenHeadAdvance &&
		retained > g.d.Cfg.FrozenRetainedMin:
		return true, "compact-rev-frozen"
	}
	return false, ""
}

// clampStepTarget is the compact-step-cap step cap — pure for tests. When
// MaxStepRevisions > 0 and the head-Tail target would jump more than
// MaxStepRevisions past compact_rev, the target is clamped so one
// cycle cannot delete the whole watch-bookmark window (informer
// 410 Gone reflector storm); the next cycles keep stepping down.
// MaxStepRevisions <= 0 disables the cap entirely.
func (g *Guard) clampStepTarget(crev, target int64) int64 {
	maxStep := g.d.Cfg.MaxStepRevisions
	if maxStep > 0 && target-crev > maxStep {
		return crev + maxStep
	}
	return target
}

// buildCompactScript renders the single-session psql script: acquire
// the advisory lock, replay UpdateCompactSQL + CompactSQL per chunk
// (each DO block is its own autocommitted statement = one txn per
// chunk, same as the bash per-chunk DO), VACUUM, unlock. The \gset +
// \if keeps every statement behind the lock check; a busy lock echoes
// the LockBusyMarker and skips everything. Each chunk's row count is
// also INSERTed into the kcg_deleted temp table and SELECTed back at
// the end: RAISE NOTICE travels on stderr, which the runner keeps
// out of stdout, so the `deleted=N` lines sumDeleted parses must be
// real query output.
func (g *Guard) buildCompactScript(cur, target int64) string {
	t := kdeps.SQLIdent(g.d.Cfg.Table)
	var b strings.Builder
	fmt.Fprintf(&b,
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS kcg_locked;\n",
		g.d.Cfg.AdvisoryLockID)
	b.WriteString("\\gset\n\\if :kcg_locked\n")
	b.WriteString("CREATE TEMP TABLE kcg_deleted(n int);\n")
	for chunks := 0; cur < target && chunks < g.d.Cfg.MaxChunks; chunks++ {
		next := cur + g.d.Cfg.ChunkRevisions
		if next > target {
			next = target
		}
		fmt.Fprintf(&b, `DO $$
DECLARE n int;
BEGIN
  UPDATE %s SET prev_revision = %d WHERE name = '%s';
  DELETE FROM %s AS kv USING (
      SELECT kp.prev_revision AS id FROM %s AS kp
      WHERE kp.name != '%s' AND kp.prev_revision != 0
        AND kp.id > %d AND kp.id <= %d
      UNION ALL
      SELECT kd.id AS id FROM %s AS kd
      WHERE kd.deleted != 0 AND kd.id > %d AND kd.id <= %d
  ) AS ks WHERE kv.id = ks.id;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO kcg_deleted VALUES (n);
  RAISE NOTICE 'deleted=%%', n;
END $$;
`, t, next, kdeps.CompactRevKey, t, t, kdeps.CompactRevKey, cur, next, t, cur, next)
		cur = next
	}
	b.WriteString("SELECT 'deleted=' || n AS deleted FROM kcg_deleted;\n")
	fmt.Fprintf(&b, "VACUUM (ANALYZE) %s;\n", t)
	fmt.Fprintf(&b, "SELECT pg_advisory_unlock(%d);\n", g.d.Cfg.AdvisoryLockID)
	b.WriteString("\\else\n\\echo '" + kdeps.LockBusyMarker + "'\n\\endif\n")
	return b.String()
}

// buildSweepScript renders the below-horizon backlog sweep: when
// the compaction marker already sits at/ahead of head-Tail there is
// no forward window to advance through, but dead rows BELOW
// compact_rev can still pile up (a marker moved without its
// deletes, or chunk ranges a previous run never reached). Rows
// under the marker are already-compacted history — watchers resume
// from compact_rev and eat a 410 Gone below it — so the same
// shadowed/deleted-row DELETE semantics run over [minID, crev] in
// bounded chunks WITHOUT the compact_rev_key UPDATE: the marker
// must not move (there is no forward progress to record), it only
// gates what may be deleted.
func (g *Guard) buildSweepScript(minID, crev int64) string {
	t := kdeps.SQLIdent(g.d.Cfg.Table)
	var b strings.Builder
	fmt.Fprintf(&b,
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS kcg_locked;\n",
		g.d.Cfg.AdvisoryLockID)
	b.WriteString("\\gset\n\\if :kcg_locked\n")
	b.WriteString("CREATE TEMP TABLE kcg_deleted(n int);\n")
	for cur, chunks := minID, 0; cur < crev && chunks < g.d.Cfg.MaxChunks; chunks++ {
		next := cur + g.d.Cfg.ChunkRevisions
		if next > crev {
			next = crev
		}
		fmt.Fprintf(&b, `DO $$
DECLARE n int;
BEGIN
  DELETE FROM %s AS kv USING (
      SELECT kp.prev_revision AS id FROM %s AS kp
      WHERE kp.name != '%s' AND kp.prev_revision != 0
        AND kp.id > %d AND kp.id <= %d
      UNION ALL
      SELECT kd.id AS id FROM %s AS kd
      WHERE kd.deleted != 0 AND kd.id > %d AND kd.id <= %d
  ) AS ks WHERE kv.id = ks.id;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO kcg_deleted VALUES (n);
  RAISE NOTICE 'deleted=%%', n;
END $$;
`, t, t, kdeps.CompactRevKey, cur, next, t, cur, next)
		cur = next
	}
	b.WriteString("SELECT 'deleted=' || n AS deleted FROM kcg_deleted;\n")
	fmt.Fprintf(&b, "VACUUM (ANALYZE) %s;\n", t)
	fmt.Fprintf(&b, "SELECT pg_advisory_unlock(%d);\n", g.d.Cfg.AdvisoryLockID)
	b.WriteString("\\else\n\\echo '" + kdeps.LockBusyMarker + "'\n\\endif\n")
	return b.String()
}

// sumDeleted totals the deleted=N notices from the chunk run.
func sumDeleted(out string) int64 {
	var total int64
	for _, m := range reDeleted.FindAllStringSubmatch(out, -1) {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil {
			total += v
		}
	}
	return total
}

// Result captures one guard run for emission + tests — was
// guardResult.
type Result struct {
	ok       bool
	fired    bool
	deleted  int64
	frozen   int64
	head     int64
	compact  int64
	rows     int64
	revAfter int64 // compact_rev re-read after the compact loop
	revSeen  bool  // revAfter is valid
	statsOK  bool  // head/compact/rows were actually read this run
	reason   string
	// backup-health backup verifier outcome — seen=false when the
	// verifier could neither measure nor create a dump this run.
	backupAge   int64
	backupValid bool
	backupSeen  bool
	notes       []string
}

// Cycle runs one guard round and emits metrics + textfile — was
// guardCycle. Returns the result for tests.
func (g *Guard) Cycle(ctx context.Context) *Result {
	res := &Result{ok: true}
	note := func(s string) { res.notes = append(res.notes, s) }

	user, pass, credOK := g.d.Creds()
	pg := g.d.PGContainerName(ctx)
	switch {
	case !credOK:
		res.ok = false
		note(fmt.Sprintf("missing .env creds (%s)", g.d.Cfg.EnvFile))
	case !g.d.ContainerRunning(ctx, pg):
		res.ok = false
		note(fmt.Sprintf("postgres container %s down", pg))
	default:
		g.guardRun(ctx, pg, user, pass, res, note)
		// backup-health: physical-backup verifier — pg_dump -Fc
		// every BackupInterval when free space allows, header
		// verified; emits kine_db_backup_{age_seconds,valid} in
		// the same textfile.
		g.backupVerify(ctx, pg, user, pass, res, note)
	}
	g.emitGuard(res)
	sum := fmt.Sprintf("head=%d compact_rev=%d rows=%d frozen=%d fired=%v "+
		"trigger=%s deleted=%d compact_rev_after=%s",
		res.head, res.compact, res.rows, res.frozen, res.fired,
		kdeps.ReasonOrDash(res.reason), res.deleted, kdeps.IntOrNA(res.revSeen, res.revAfter))
	if res.ok {
		logger().Info("kine-compact-guard OK: " + sum)
		g.d.M.Cycles.WithLabelValues("compact-guard", "ok").Inc()
	} else {
		logger().Warn("kine-compact-guard FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		g.d.M.Cycles.WithLabelValues("compact-guard", "fail").Inc()
	}
	return res
}

// guardRun does the stats read, freeze bookkeeping, trigger decision
// and (on fire) the locked compact session.
func (g *Guard) guardRun(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {

	out, err := g.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE((SELECT MAX(id) FROM %s),0), "+
			"COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
			"COUNT(*), COALESCE(MIN(id),0) FROM %[1]s",
		kdeps.SQLIdent(g.d.Cfg.Table), kdeps.SQLIdent(g.d.Cfg.Table), kdeps.CompactRevKey))
	if err != nil {
		res.ok = false
		note(fmt.Sprintf("stats query fail: %v", err))
		return
	}
	head, crev, rows, minID, perr := kdeps.ParseQuad(out)
	if perr != nil {
		res.ok = false
		note(fmt.Sprintf("stats unparsed: %v", perr))
		return
	}
	res.head, res.compact, res.rows = head, crev, rows
	res.statsOK = true

	// compact_rev frozen detection: identical compact_rev while head
	// advanced = neither kine nor apiserver lived long enough to
	// compact (OOM-loop signature). A guard fire advances compact_rev
	// itself, so the counter resets naturally on the next run.
	prev := g.readGuardState()
	res.frozen = 0
	if prev.seen && crev == prev.compactRev && head > prev.head {
		res.frozen = prev.freeze + 1
	}
	retained := head - crev
	trig, reason := g.guardTrigger(head, crev, rows, retained, res.frozen, prev)
	g.writeGuardState(head, crev, res.frozen)
	if !trig {
		return
	}
	res.reason = reason
	// head <= Tail means the entire retained history already fits
	// inside the watch tail — there is no safely-deletable range.
	// compacting to head here would advance compact_rev past every
	// revision a watcher could resume from (apiserver 410 Gone
	// storm), so skip the session entirely. Unreachable under the
	// default thresholds (every trigger needs retained/rows far
	// above Tail) but config drift must not open the hole.
	if head <= g.d.Cfg.Tail {
		note(fmt.Sprintf("compact skipped: head=%d <= tail=%d — nothing safely deletable",
			head, g.d.Cfg.Tail))
		return
	}
	res.fired = true

	// Marker off-by-one parity with the shell: compact to head-TAIL,
	// except when the marker is already ahead (then hold at crev).
	// target <= crev implies crev > 0 — the head <= Tail / crev == 0
	// combinations that used to fall back to target=head are skipped
	// above, so no never-compacted overshoot remains.
	target := head - g.d.Cfg.Tail
	sweepBelow := false
	if target <= crev {
		// Fewer than Tail new revisions since the last compact —
		// pushing compact_revision to head would erase the watch
		// tail buffer and storm the apiserver with 410 Gone. Hold
		// at crev instead so the DELETE only sweeps history.
		target = crev
		// rows-debt with the marker already at/ahead of the safe
		// horizon: the forward compact has NO window to advance
		// through (cur == target → zero chunks), yet dead rows
		// BELOW compact_rev keep piling up — the table stays over
		// RowsMax and every cycle re-fires into an empty session.
		// Sweep [minID, crev] in bounded chunks instead: rows under
		// the marker are already-compacted history, safe to drop
		// WITHOUT advancing compact_rev_key (there is no forward
		// progress to record — the marker only gates deletions).
		sweepBelow = rows > g.d.Cfg.RowsMax && minID < crev
		if sweepBelow {
			note(fmt.Sprintf(
				"below-horizon sweep: rows=%d min_id=%d compact_rev=%d",
				rows, minID, crev))
		}
	}
	// compact-step-cap: never step the whole window in one cycle.
	target = g.clampStepTarget(crev, target)
	t0 := g.d.Cfg.Clock.Now()
	var script string
	if sweepBelow {
		script = g.buildSweepScript(minID, crev)
	} else {
		script = g.buildCompactScript(crev, target)
	}
	sout, err := g.d.PsqlScript(ctx, pg, user, pass, script)
	if err != nil && g.d.LongBudgetExceeded(t0, err) {
		// The client kill can orphan the server-side session —
		// still holding the advisory lock. Reap it now.
		if n, rerr := g.d.ReapOrphanedMaintSessions(ctx, pg, user, pass); rerr != nil {
			note(fmt.Sprintf("orphan-reap-fail: %v", rerr))
		} else if n > 0 {
			note(fmt.Sprintf("terminated %d orphaned maintenance backend(s) after exec timeout", n))
			logger().Warn("kinedb: terminated orphaned maintenance backends after exec timeout",
				"count", n)
		}
	}
	switch {
	case err != nil:
		res.ok = false
		note(fmt.Sprintf("compact-fail: %v", err))
	case strings.Contains(sout, kdeps.LockBusyMarker):
		res.fired = false
		note("guard already running")
	default:
		res.deleted = sumDeleted(sout)
		g.writeGuardCompactTS(g.d.Cfg.Clock.Now().Unix())
		// The bash re-read compact_rev + rows after the loop —
		// how far the chunks actually got and the post-VACUUM
		// table size. Failure only means the after-gauges go
		// stale, never the run.
		if aout, aerr := g.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
			"SELECT COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
				"COUNT(*) FROM %[1]s",
			kdeps.SQLIdent(g.d.Cfg.Table), kdeps.CompactRevKey)); aerr == nil {
			if after, rows, perr := kdeps.ParsePair(aout); perr == nil {
				res.revAfter, res.revSeen = after, true
				res.rows = rows
			}
		}
	}
}

// emitGuard renders the textfile and updates the collectors.
func (g *Guard) emitGuard(res *Result) {
	var p promfile.Builder
	ok := 0.0
	if res.ok {
		ok = 1
	}
	p.Gauge("kine_db_guard_ok",
		"Compact guard result (1 = ok/skip, 0 = fail)", ok)
	g.d.M.GuardOK.Set(ok)
	fired := 0.0
	if res.fired {
		fired = 1
	}
	p.Gauge("kine_db_guard_fired",
		"1 when the last guard run executed a compact session", fired)
	g.d.M.GuardFired.Set(fired)
	// freeze_cycles + kine_db_rows come out of the stats read —
	// kine_db_rows lives here, not in the probe textfile, because
	// the COUNT(*) it needs seq-scans the table (10-min cadence)
	// and emitting it in both files would fail the scrape
	// (duplicate series across textfiles). Both gauges are skipped
	// when the stats read failed — a fabricated 0 overwriting a
	// meaningful freeze count (or row count) is worse than stale.
	if res.statsOK {
		p.Gauge("kine_db_guard_freeze_cycles",
			"Consecutive runs compact_rev stayed frozen while head advanced",
			float64(res.frozen))
		g.d.M.GuardFreeze.Set(float64(res.frozen))
		p.Gauge("kine_db_rows",
			"Row count of the kine table — kine boot fill cost",
			float64(res.rows))
		g.d.M.Rows.Set(float64(res.rows))
	}
	if res.revSeen {
		p.Gauge("kine_db_guard_compact_rev_after",
			"compact_rev re-read after the last completed compact run",
			float64(res.revAfter))
		g.d.M.GuardRevAfter.Set(float64(res.revAfter))
	}
	p.Gauge("kine_db_guard_last_deleted_rows",
		"Rows deleted by the last compact run", float64(res.deleted))
	g.d.M.GuardLastDeleted.Set(float64(res.deleted))
	lastCompact := float64(g.readGuardCompactTS())
	p.Gauge("kine_db_guard_last_compact_timestamp_seconds",
		"Timestamp of the last completed compact run", lastCompact)
	g.d.M.GuardLastCompact.Set(lastCompact)
	ts := float64(g.d.Cfg.Clock.Now().Unix())
	p.Gauge("kine_db_guard_last_run_timestamp_seconds",
		"Last guard run", ts)
	g.d.M.GuardLastRun.Set(ts)
	// kine-churn: the probe loop's top-5 churn sample renders here —
	// this file owns the churn series (the probe's own .prom must
	// never duplicate it). The probe goroutine refreshes ChurnTop
	// asynchronously — snapshot it under ChurnMu. And the GaugeVec
	// is Reset+repopulated rather than merged: a resource that
	// falls out of the top-5 must lose its series instead of
	// pinning a stale value on /metrics forever.
	g.d.ChurnMu.RLock()
	churnTop := append([]kdeps.ChurnEntry(nil), g.d.ChurnTop...)
	churnKeys := append([]kdeps.ChurnKeyEntry(nil), g.d.ChurnKeys...)
	g.d.ChurnMu.RUnlock()
	g.d.M.TopChurn.Reset()
	for _, e := range churnTop {
		p.GaugeLabels("kine_db_top_churn_revisions_5m",
			"Top-5 resource prefixes by revision count in the last 5-minute window",
			fmt.Sprintf("resource=%q", e.Resource), float64(e.Revs))
		g.d.M.TopChurn.WithLabelValues(e.Resource).Set(float64(e.Revs))
	}
	// selfheal-alert-coverage hot-key twin: same window, full Kine keys — the SSA
	// managedFields ping-pong names its victim object. Same
	// Reset+repopulate contract: a key falling out of the top-5
	// loses its series instead of pinning a stale value.
	g.d.M.TopHotkey.Reset()
	for _, e := range churnKeys {
		p.GaugeLabels("kine_db_top_hotkey_revisions_5m",
			"Top-5 full Kine object keys by revision count in the last 5-minute window (>=50 revs, leases/events excluded)",
			fmt.Sprintf("key=%q", e.Key), float64(e.Revs))
		g.d.M.TopHotkey.WithLabelValues(e.Key).Set(float64(e.Revs))
	}
	// backup-health: physical-backup verifier series — seen-gated like
	// the stats series: an unmeasured cycle must not fabricate a
	// passing backup state.
	if res.backupSeen {
		valid := 0.0
		if res.backupValid {
			valid = 1
		}
		p.Gauge("kine_db_backup_age_seconds",
			"Age of the newest physical pg_dump in the backup dir",
			float64(res.backupAge))
		p.Gauge("kine_db_backup_valid",
			"1 when the newest physical pg_dump passed header verification",
			valid)
		g.d.M.BackupAge.Set(float64(res.backupAge))
		g.d.M.BackupValid.Set(valid)
	}
	g.d.EmitTextfile("kine-compact-guard.prom", &p)
}
