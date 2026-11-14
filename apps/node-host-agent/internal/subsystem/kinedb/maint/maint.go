// Package maint ports kine-db-maint.sh — the daily maintenance job
// on the kine DB VM.
//
// Why it exists (incident 2026-09-28): the kine table's index bloat
// made `SELECT MAX(id)` take seconds, pushing kine init past the k0s
// health-check window and crash-looping remote controllers.
// autovacuum only reclaims dead tuples — it never reindexes and never
// shrinks the heap — so this job runs:
//
//	reindex  REINDEX TABLE CONCURRENTLY kine — always (cheap on a
//	         small table, SHARE UPDATE EXCLUSIVE lock). invalid-index-reaper:
//	         preceded by the invalid-index reaper — an interrupted
//	         REINDEX CONCURRENTLY / pg_repack leaves *_ccnew / *_ccold
//	         shells with indisvalid=false; they cost every INSERT,
//	         serve no query, and trip the next reindex, so they are
//	         dropped first (DROP INDEX CONCURRENTLY).
//	freeze   VACUUM (FREEZE, ANALYZE) once MAX(age(datfrozenxid))
//	         crosses 150M — the wraparound remediation rides this
//	         window because a FREEZE vacuum is a full-table rewrite
//	         storm, not a probe-time action (freeze.go).
//	repack   pg_repack --no-superuser-check --no-order
//	         --wait-timeout=10 --no-kill-backend -t public.kine
//	         — ONLY when the heap is genuinely bloated
//	         (dead_tuple_percent > 40 AND heap > 200MB, measured via
//	         pg_stat_user_tables + pg_relation_size) and the data
//	         filesystem has 2.5x(heap+wal) headroom. Online shadow
//	         copy, needs ~2x table space transiently.
//
// The probe and compact-guard loops live in sibling packages;
// everything shared goes through kdeps.Deps.
package maint

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

const (
	// lastMaintFile — the heavy-block epoch under GuardStateDir:
	// the unix second the last full REINDEX/FREEZE/repack run
	// completed (the same last-* file contract as the guard).
	lastMaintFile = "last-maint-run"
	// maintEpochGrace bounds the skip window BELOW the maintenance
	// interval (kdeps.DefaultMaintInterval). Failure mode without
	// it: the cycle cadence lands just inside a full-length window
	// (say hour 23 of 24) → the startup run SKIPS → the next look
	// is another interval away → real maintenance slides to ~47h
	// since the last heavy block. With the grace, a restart that
	// late re-runs the block up to 2h "early" instead of pushing it
	// a full interval late.
	maintEpochGrace = 2 * time.Hour
	// maintEpochWindow — a heavy block younger than this skips the
	// next cycle's REINDEX + VACUUM FREEZE + pg_repack. cycle.RunAll
	// fires Cycle immediately on every agent (re)start, and without
	// the epoch a restart during a reindex storm replays the storm
	// from second zero. Derived from the interval (not spelled 24h)
	// so the skip window can never outgrow the cadence it gates.
	maintEpochWindow = kdeps.DefaultMaintInterval - maintEpochGrace
)

// buildHeavyScript renders the single-session psql script the heavy
// block runs in: acquire the compact guard's advisory lock, REINDEX
// TABLE CONCURRENTLY, VACUUM (FREEZE, ANALYZE) when the XID age
// triggered, unlock. The \gset + \if keeps every statement behind
// the lock check; a busy lock echoes kdeps.LockBusyMarker and skips
// everything (probe deadTupleVacuum parity).
func (m *Maint) buildHeavyScript(freeze bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "REINDEX TABLE CONCURRENTLY %s;\n", kdeps.SQLIdent(m.d.Cfg.Table))
	if freeze {
		fmt.Fprintf(&b, "VACUUM (FREEZE, ANALYZE) %s;\n", kdeps.SQLIdent(m.d.Cfg.Table))
	}
	return kdeps.WrapAdvisoryLockScript(m.d.Cfg.AdvisoryLockID, "km_locked", b.String())
}

// buildLockProbe renders a try-lock/unlock probe for work that runs
// outside psql (pg_repack) — a busy lock skips the caller this cycle.
func (m *Maint) buildLockProbe() string {
	return kdeps.WrapAdvisoryLockScript(m.d.Cfg.AdvisoryLockID, "km_probe", "")
}

// deadTuplePct returns n_dead_tup as a percentage of estimated rows —
// 0 when the stats view has no rows for the table (fresh stats or an
// empty table never triggers repack).
func deadTuplePct(dead, live int64) int64 {
	total := dead + live
	if total <= 0 {
		return 0
	}
	return dead * 100 / total
}

// Result captures one maintenance run for emission + tests — was
// maintResult.
type Result struct {
	okReindex   bool
	okRepack    bool   // skip counts as ok — a ran-and-failed repack (or a failed assessment) flips it
	okFreeze    bool   // same for the XID freeze vacuum
	repackState string // skipped|done|fail|no-binary|assess-fail
	freezeState string // ""|skipped|done|fail — "" until the XID read lands
	xidAge      int64
	xidSeen     bool // MAX(age(datfrozenxid)) was actually read this run
	heapBytes   int64
	indexBytes  int64
	deadPct     int64
	statsOK     bool // sizes/dead-tuple stats were actually read this run
	// invalid-index-reaper invalid-index reaper tallies.
	invalidDropped int
	invalidKept    int // non-ccnew/ccold invalids left for an operator
	// urgent-reindex (bloat.go) — the post-storm out-of-band gate:
	// off|cooldown|skipped-lock-busy|done|fail (only fail flips
	// okUrgent; skips count as ok like the repack gates).
	urgentState string
	okUrgent    bool
	notes       []string
}

// Maint runs the daily maintenance job — the kine-db-maint.sh port.
// It keeps no state of its own: config, metrics and the exec
// plumbing live on the shared *kdeps.Deps.
type Maint struct {
	d *kdeps.Deps
}

// New returns the maintenance loop over d.
func New(d *kdeps.Deps) *Maint { return &Maint{d: d} }

// Cycle runs one maintenance round and emits metrics + textfile —
// was maintCycle. Returns the result for tests.
func (m *Maint) Cycle(ctx context.Context) *Result {
	res := &Result{okRepack: true, okFreeze: true, okUrgent: true,
		repackState: "skipped"}
	note := func(s string) { res.notes = append(res.notes, s) }

	user, pass, credOK := m.d.Creds()
	pg := m.d.PGContainerName(ctx)
	switch {
	case !credOK:
		note(fmt.Sprintf("missing .env creds (%s)", m.d.Cfg.EnvFile))
	case !m.d.ContainerRunning(ctx, pg):
		note(fmt.Sprintf("postgres container %s down", pg))
	default:
		m.maintRun(ctx, pg, user, pass, res, note, !m.maintEpochFresh())
	}
	m.emitMaint(res)
	sum := fmt.Sprintf("reindex=%v repack=%s freeze=%s urgent=%s heap=%dB idx=%dB "+
		"dead=%d%% xid=%s",
		res.okReindex, res.repackState, kdeps.ReasonOrDash(res.freezeState),
		kdeps.ReasonOrDash(res.urgentState),
		res.heapBytes, res.indexBytes, res.deadPct,
		kdeps.IntOrNA(res.xidSeen, res.xidAge))
	if res.okReindex && res.okRepack && res.okFreeze && res.okUrgent {
		logger().Info("kine-db-maint OK: " + sum)
		m.d.M.Cycles.WithLabelValues("maint", "ok").Inc()
	} else {
		logger().Warn("kine-db-maint FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		m.d.M.Cycles.WithLabelValues("maint", "fail").Inc()
	}
	return res
}

// maintEpochFresh reports whether a heavy maint block completed less
// than maintEpochWindow ago (the interval minus the boundary grace —
// see maintEpochGrace for the ~47h failure mode) — ReadIntFile
// failing on a missing epoch file reads as "never ran", so a fresh
// install always runs the heavy block.
func (m *Maint) maintEpochFresh() bool {
	epoch, err := kdeps.ReadIntFile(
		filepath.Join(m.d.Cfg.GuardStateDir, lastMaintFile))
	if err != nil {
		return false
	}
	return m.d.Cfg.Clock.Now().Sub(time.Unix(epoch, 0)) < maintEpochWindow
}

// stampMaintEpoch records the heavy block's completion under
// GuardStateDir — only the daemon stamps it (ReadOnly is the
// check-kine-db CLI contract: no state-file writes).
func (m *Maint) stampMaintEpoch() {
	if m.d.Cfg.ReadOnly {
		return
	}
	kdeps.WriteIntFile(
		filepath.Join(m.d.Cfg.GuardStateDir, lastMaintFile),
		m.d.Cfg.Clock.Now().Unix())
}

// reapOrphanedMaint is the exec-timeout backstop for the heavy
// script and pg_repack: when the long-budget client is killed the
// server-side session can survive it, so terminate our own
// maintenance backends that are old enough to be orphans. Best
// effort — a failed reap only notes.
func (m *Maint) reapOrphanedMaint(ctx context.Context, pg, user, pass string,
	note func(string)) {
	n, err := m.d.ReapOrphanedMaintSessions(ctx, pg, user, pass)
	switch {
	case err != nil:
		note(fmt.Sprintf("orphan-reap-fail: %v", err))
	case n > 0:
		note(fmt.Sprintf("terminated %d orphaned maintenance backend(s) after exec timeout", n))
		logger().Warn("kinedb: terminated orphaned maintenance backends after exec timeout",
			"count", n)
	}
}

// readSizes reads the heap/index bytes + dead/live-tuple estimate the
// gauges and the repack gate consume (the (c) block of maintRun).
func (m *Maint) readSizes(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {
	out, err := m.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT pg_relation_size(%[1]s), pg_indexes_size(%[1]s), "+
			"COALESCE((SELECT n_dead_tup FROM pg_stat_user_tables WHERE relname=%[1]s),0), "+
			"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname=%[1]s),0)",
		kdeps.SQLQuote(m.d.Cfg.Table)))
	if err == nil {
		heap, idx, dead, live, perr := kdeps.ParseQuad(out)
		if perr == nil {
			res.heapBytes = heap
			res.indexBytes = idx
			res.deadPct = deadTuplePct(dead, live)
			res.statsOK = true
		} else {
			note(fmt.Sprintf("sizes-unparsed: %v", perr))
		}
	} else {
		note(fmt.Sprintf("sizes-fail: %v", err))
	}
}

// reapInvalidIndexes — invalid-index-reaper: drop the invalid index shells an
// interrupted REINDEX CONCURRENTLY / pg_repack leaves on the kine
// table. Only the *_ccnew / *_ccold names PostgreSQL itself mints
// are auto-dropped — any other invalid index is noted and kept for
// an operator (dropping a live application's index would be data
// loss of a different kind). DROP INDEX CONCURRENTLY cannot run in
// a transaction, so each drop is its own -qc statement under the
// long budget (CONCURRENTLY waits on concurrent snapshots).
func (m *Maint) reapInvalidIndexes(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {
	out, err := m.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT indexrelid::regclass::text FROM pg_index "+
			"WHERE NOT indisvalid AND indrelid = %s::regclass",
		kdeps.SQLQuote(m.d.Cfg.Table)))
	if err != nil {
		note(fmt.Sprintf("invalid-index-list-fail: %v", err))
		return
	}
	for _, idx := range kdeps.ParseGIDs(out) {
		// regclass::text may be schema-qualified (public.foo) or
		// double-quoted — the suffix + identifier checks apply to
		// the bare index name.
		base := idx
		if i := strings.LastIndexByte(base, '.'); i >= 0 {
			base = base[i+1:]
		}
		base = strings.Trim(base, `"`)
		switch {
		case !kdeps.ReTableIdent.MatchString(base):
			note(fmt.Sprintf("invalid-index %q skipped (unsafe name)", idx))
		case !strings.HasSuffix(base, "_ccnew") &&
			!strings.HasSuffix(base, "_ccold"):
			note(fmt.Sprintf("invalid-index %s kept (not a _ccnew/_ccold orphan)", base))
			res.invalidKept++
			logger().Warn("kinedb: invalid index on kine table kept (not a reindex orphan)",
				"index", base)
		default:
			if _, derr := m.d.ExecLongEnv(ctx, m.d.PsqlMaintEnv(pass), m.d.PsqlMaintArgs(pg, user, false,
				"-qc", "DROP INDEX CONCURRENTLY IF EXISTS "+
					kdeps.SQLIdent(base)), ""); derr != nil {
				note(fmt.Sprintf("drop-index-%s-fail: %v", base, derr))
				continue
			}
			res.invalidDropped++
			note("dropped invalid index " + base)
			logger().Warn("kinedb: dropped orphaned invalid index",
				"index", base)
		}
	}
}

// emitMaint renders the textfile and updates the collectors.
func (m *Maint) emitMaint(res *Result) {
	var p promfile.Builder
	reindex, repack := 0.0, 0.0
	if res.okReindex {
		reindex = 1
	}
	if res.okRepack {
		repack = 1
	}
	p.GaugeLabels("kine_db_maint_ok",
		"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
		`check="reindex"`, reindex)
	p.GaugeLabels("kine_db_maint_ok",
		"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
		`check="repack"`, repack)
	m.d.M.MaintOK.WithLabelValues("reindex").Set(reindex)
	m.d.M.MaintOK.WithLabelValues("repack").Set(repack)
	// vacuum_freeze only appears once the XID read landed — same
	// seen-gating as relation_bytes: an unmeasured cycle must not
	// fabricate a passing check.
	if res.xidSeen {
		freeze := 1.0
		if res.freezeState == "fail" {
			freeze = 0
		}
		p.GaugeLabels("kine_db_maint_ok",
			"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
			`check="vacuum_freeze"`, freeze)
		m.d.M.MaintOK.WithLabelValues("vacuum_freeze").Set(freeze)
	}
	ts := float64(m.d.Cfg.Clock.Now().Unix())
	p.Gauge("kine_db_maint_last_run_timestamp_seconds",
		"Last maintenance run", ts)
	m.d.M.MaintLastRun.Set(ts)
	// urgent-reindex (bloat.go): the maint_ok check renders only once
	// the gate has actually been evaluated (a cycle without live
	// postgres never reaches the gate — no fabricated pass), and the
	// timestamp lands only on a completed out-of-band reindex.
	if res.urgentState != "" {
		urgent := 1.0
		if res.urgentState == "fail" {
			urgent = 0
		}
		p.GaugeLabels("kine_db_maint_ok",
			"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
			`check="urgent_reindex"`, urgent)
		m.d.M.MaintOK.WithLabelValues("urgent_reindex").Set(urgent)
	}
	if res.urgentState == "done" {
		p.Gauge("kine_db_urgent_reindex_last_run_timestamp_seconds",
			"Last post-storm out-of-band REINDEX TABLE CONCURRENTLY.", ts)
		m.d.M.UrgentReindexLastRun.Set(ts)
	}
	// relation_bytes comes out of the stats read — emitGuard's
	// statsOK gating applied here too: on assess-fail a fabricated
	// 0 overwriting a meaningful size is worse than a stale gauge.
	if res.statsOK {
		p.GaugeLabels("kine_db_maint_relation_bytes",
			"Heap/index size of the kine table", `kind="heap"`,
			float64(res.heapBytes))
		p.GaugeLabels("kine_db_maint_relation_bytes",
			"Heap/index size of the kine table", `kind="indexes"`,
			float64(res.indexBytes))
		m.d.M.MaintRelBytes.WithLabelValues("heap").Set(float64(res.heapBytes))
		m.d.M.MaintRelBytes.WithLabelValues("indexes").Set(float64(res.indexBytes))
	}
	m.d.EmitTextfile("kine-db-maint.prom", &p)
}
