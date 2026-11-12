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
