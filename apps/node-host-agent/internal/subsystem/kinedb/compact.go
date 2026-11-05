// compact.go — the 10-minute emergency compactor
// (kine-compact-guard.sh port).
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
// freeze-cycles, last-compact-ts.
package kinedb

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/promfile"
)

// Guard state file names under GuardStateDir.
const (
	guardFileLastHead       = "last-head"
	guardFileLastCompactRev = "last-compact-rev"
	guardFileFreeze         = "freeze-cycles"
	guardFileCompactTS      = "last-compact-ts"
)

// guardState is the cross-run history read from GuardStateDir.
type guardState struct {
	head       int64
	compactRev int64
	freeze     int64
	seen       bool // false when the state files are absent/unreadable
}

func (k *KineDB) readGuardState() guardState {
	dir := k.cfg.GuardStateDir
	head, errH := readIntFile(filepath.Join(dir, guardFileLastHead))
	crev, errC := readIntFile(filepath.Join(dir, guardFileLastCompactRev))
	fz, _ := readIntFile(filepath.Join(dir, guardFileFreeze))
	return guardState{head: head, compactRev: crev, freeze: fz,
		seen: errH == nil && errC == nil}
}

func (k *KineDB) writeGuardState(head, compactRev, freeze int64) {
	dir := k.cfg.GuardStateDir
	writeIntFile(filepath.Join(dir, guardFileLastHead), head)
	writeIntFile(filepath.Join(dir, guardFileLastCompactRev), compactRev)
	writeIntFile(filepath.Join(dir, guardFileFreeze), freeze)
}

func (k *KineDB) readGuardCompactTS() int64 {
	v, _ := readIntFile(filepath.Join(k.cfg.GuardStateDir, guardFileCompactTS))
	return v
}

func (k *KineDB) writeGuardCompactTS(ts int64) {
	writeIntFile(filepath.Join(k.cfg.GuardStateDir, guardFileCompactTS), ts)
}

// guardTrigger is the pure trigger predicate — separated for tests.
func (k *KineDB) guardTrigger(head, compactRev, rows, retained, freeze int64, prev guardState) (bool, string) {
	switch {
	case retained > k.cfg.RetainedMax:
		return true, "retained-debt"
	case rows > k.cfg.RowsMax:
		return true, "rows-debt"
	case prev.seen && freeze >= k.cfg.FrozenCycles &&
		head > prev.head+k.cfg.FrozenHeadAdvance &&
		retained > k.cfg.FrozenRetainedMin:
		return true, "compact-rev-frozen"
	}
	return false, ""
}

// buildCompactScript renders the single-session psql script: acquire
// the advisory lock, replay UpdateCompactSQL + CompactSQL per chunk
// (each DO block is its own autocommitted statement = one txn per
// chunk, same as the bash per-chunk DO), VACUUM, unlock. The \gset +
// \if keeps every statement behind the lock check; a busy lock echoes
// the lockBusyMarker and skips everything. Each chunk's row count is
// also INSERTed into the kcg_deleted temp table and SELECTed back at
// the end: RAISE NOTICE travels on stderr, which the runner keeps
// out of stdout, so the `deleted=N` lines sumDeleted parses must be
// real query output.
func (k *KineDB) buildCompactScript(cur, target int64) string {
	t := k.cfg.Table
	var b strings.Builder
	fmt.Fprintf(&b,
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS kcg_locked;\n",
		k.cfg.AdvisoryLockID)
	b.WriteString("\\gset\n\\if :kcg_locked\n")
	b.WriteString("CREATE TEMP TABLE kcg_deleted(n int);\n")
	for chunks := 0; cur < target && chunks < k.cfg.MaxChunks; chunks++ {
		next := cur + k.cfg.ChunkRevisions
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
`, t, next, compactRevKey, t, t, compactRevKey, cur, next, t, cur, next)
		cur = next
	}
	b.WriteString("SELECT 'deleted=' || n AS deleted FROM kcg_deleted;\n")
	fmt.Fprintf(&b, "VACUUM (ANALYZE) %s;\n", t)
	fmt.Fprintf(&b, "SELECT pg_advisory_unlock(%d);\n", k.cfg.AdvisoryLockID)
	b.WriteString("\\else\n\\echo '" + lockBusyMarker + "'\n\\endif\n")
	return b.String()
}

func reasonOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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

// guardResult captures one guard run for emission + tests.
type guardResult struct {
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
	notes    []string
}

// guardCycle runs one guard round and emits metrics + textfile.
// Returns the result for tests.
func (k *KineDB) guardCycle(ctx context.Context) *guardResult {
	res := &guardResult{ok: true}
	note := func(s string) { res.notes = append(res.notes, s) }

	user, pass, credOK := k.creds()
	pg := k.pgContainerName(ctx)
	switch {
	case !credOK:
		res.ok = false
		note(fmt.Sprintf("missing .env creds (%s)", k.cfg.EnvFile))
	case !k.containerRunning(ctx, pg):
		res.ok = false
		note(fmt.Sprintf("postgres container %s down", pg))
	default:
		k.guardRun(ctx, pg, user, pass, res, note)
	}
	k.emitGuard(res)
	sum := fmt.Sprintf("head=%d compact_rev=%d rows=%d frozen=%d fired=%v "+
		"trigger=%s deleted=%d compact_rev_after=%s",
		res.head, res.compact, res.rows, res.frozen, res.fired,
		reasonOrDash(res.reason), res.deleted, intOrNA(res.revSeen, res.revAfter))
	if res.ok {
		logger().Info("kine-compact-guard OK: " + sum)
		k.m.cycles.WithLabelValues("compact-guard", "ok").Inc()
	} else {
		logger().Warn("kine-compact-guard FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		k.m.cycles.WithLabelValues("compact-guard", "fail").Inc()
	}
	return res
}

// guardRun does the stats read, freeze bookkeeping, trigger decision
// and (on fire) the locked compact session.
func (k *KineDB) guardRun(ctx context.Context, pg, user, pass string,
	res *guardResult, note func(string)) {

	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE((SELECT MAX(id) FROM %s),0), "+
			"COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
			"COUNT(*) FROM %[1]s",
		k.cfg.Table, k.cfg.Table, compactRevKey))
	if err != nil {
		res.ok = false
		note(fmt.Sprintf("stats query fail: %v", err))
		return
	}
	head, crev, rows, perr := parseTriple(out)
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
	prev := k.readGuardState()
	res.frozen = 0
	if prev.seen && crev == prev.compactRev && head > prev.head {
		res.frozen = prev.freeze + 1
	}
	retained := head - crev
	trig, reason := k.guardTrigger(head, crev, rows, retained, res.frozen, prev)
	k.writeGuardState(head, crev, res.frozen)
	if !trig {
		return
	}
	res.reason = reason
	res.fired = true

	// Marker off-by-one parity with the shell: compact to head-TAIL,
	// except when the marker is already ahead (then to head).
	target := head - k.cfg.Tail
	if target <= crev {
		target = head
	}
	sout, err := k.psqlScript(ctx, pg, user, pass,
		k.buildCompactScript(crev, target))
	switch {
	case err != nil:
		res.ok = false
		note(fmt.Sprintf("compact-fail: %v", err))
	case strings.Contains(sout, lockBusyMarker):
		res.fired = false
		note("guard already running")
	default:
		res.deleted = sumDeleted(sout)
		k.writeGuardCompactTS(k.cfg.nowFn().Unix())
		// The bash re-read compact_rev + rows after the loop —
		// how far the chunks actually got and the post-VACUUM
		// table size. Failure only means the after-gauges go
		// stale, never the run.
		if aout, aerr := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
			"SELECT COALESCE((SELECT MAX(prev_revision) FROM %s WHERE name='%s'),0), "+
				"COUNT(*) FROM %[1]s",
			k.cfg.Table, compactRevKey)); aerr == nil {
			if after, rows, perr := parsePair(aout); perr == nil {
				res.revAfter, res.revSeen = after, true
				res.rows = rows
			}
		}
	}
}

// emitGuard renders the textfile and updates the collectors.
func (k *KineDB) emitGuard(res *guardResult) {
	var p promfile.Builder
	ok := 0.0
	if res.ok {
		ok = 1
	}
	p.Gauge("kine_db_guard_ok",
		"Compact guard result (1 = ok/skip, 0 = fail)", ok)
	k.m.guardOK.Set(ok)
	fired := 0.0
	if res.fired {
		fired = 1
	}
	p.Gauge("kine_db_guard_fired",
		"1 when the last guard run executed a compact session", fired)
	k.m.guardFired.Set(fired)
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
		k.m.guardFreeze.Set(float64(res.frozen))
		p.Gauge("kine_db_rows",
			"Row count of the kine table — kine boot fill cost",
			float64(res.rows))
		k.m.rows.Set(float64(res.rows))
	}
	if res.revSeen {
		p.Gauge("kine_db_guard_compact_rev_after",
			"compact_rev re-read after the last completed compact run",
			float64(res.revAfter))
		k.m.guardRevAfter.Set(float64(res.revAfter))
	}
	p.Gauge("kine_db_guard_last_deleted_rows",
		"Rows deleted by the last compact run", float64(res.deleted))
	k.m.guardLastDeleted.Set(float64(res.deleted))
	lastCompact := float64(k.readGuardCompactTS())
	p.Gauge("kine_db_guard_last_compact_timestamp_seconds",
		"Timestamp of the last completed compact run", lastCompact)
	k.m.guardLastCompact.Set(lastCompact)
	ts := float64(k.cfg.nowFn().Unix())
	p.Gauge("kine_db_guard_last_run_timestamp_seconds",
		"Last guard run", ts)
	k.m.guardLastRun.Set(ts)
	k.emitTextfile("kine-compact-guard.prom", &p)
}
