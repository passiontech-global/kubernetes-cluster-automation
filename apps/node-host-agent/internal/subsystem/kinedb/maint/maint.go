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
//	         small table, SHARE UPDATE EXCLUSIVE lock). W12-CP2:
//	         preceded by the invalid-index reaper — an interrupted
//	         REINDEX CONCURRENTLY / pg_repack leaves *_ccnew / *_ccold
//	         shells with indisvalid=false; they cost every INSERT,
//	         serve no query, and trip the next reindex, so they are
//	         dropped first (DROP INDEX CONCURRENTLY).
//	freeze   VACUUM (FREEZE, ANALYZE) once MAX(age(datfrozenxid))
//	         crosses 150M — the wraparound remediation rides this
//	         window because a FREEZE vacuum is a full-table rewrite
//	         storm, not a probe-time action (freeze.go).
//	repack   pg_repack --no-superuser-check --no-order -t public.kine
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
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

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
	// W12-CP2 invalid-index reaper tallies.
	invalidDropped int
	invalidKept    int // non-ccnew/ccold invalids left for an operator
	notes          []string
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
	res := &Result{okRepack: true, okFreeze: true, repackState: "skipped"}
	note := func(s string) { res.notes = append(res.notes, s) }

	user, pass, credOK := m.d.Creds()
	pg := m.d.PGContainerName(ctx)
	switch {
	case !credOK:
		note(fmt.Sprintf("missing .env creds (%s)", m.d.Cfg.EnvFile))
	case !m.d.ContainerRunning(ctx, pg):
		note(fmt.Sprintf("postgres container %s down", pg))
	default:
		m.maintRun(ctx, pg, user, pass, res, note)
	}
	m.emitMaint(res)
	sum := fmt.Sprintf("reindex=%v repack=%s freeze=%s heap=%dB idx=%dB "+
		"dead=%d%% xid=%s",
		res.okReindex, res.repackState, kdeps.ReasonOrDash(res.freezeState),
		res.heapBytes, res.indexBytes, res.deadPct,
		kdeps.IntOrNA(res.xidSeen, res.xidAge))
	if res.okReindex && res.okRepack && res.okFreeze {
		logger().Info("kine-db-maint OK: " + sum)
		m.d.M.Cycles.WithLabelValues("maint", "ok").Inc()
	} else {
		logger().Warn("kine-db-maint FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		m.d.M.Cycles.WithLabelValues("maint", "fail").Inc()
	}
	return res
}

func (m *Maint) maintRun(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {

	// (a0) W12-CP2 invalid-index reaper — BEFORE the reindex: an
	// interrupted REINDEX CONCURRENTLY or pg_repack leaves *_ccnew /
	// *_ccold shells with indisvalid=false, and those shells make
	// the next reindex error out ("cannot reindex invalid index")
	// while still taxing every INSERT. Best-effort: a failed
	// listing or drop only notes, never fails the maint run.
	m.reapInvalidIndexes(ctx, pg, user, pass, res, note)

	// (a) REINDEX CONCURRENTLY — always, cheap on a small table.
	if _, err := m.d.ExecLongEnv(ctx, kdeps.PsqlPassEnv(pass), m.d.PsqlArgs(pg, user, false,
		"-qc", "REINDEX TABLE CONCURRENTLY "+kdeps.SQLIdent(m.d.Cfg.Table)), ""); err == nil {
		res.okReindex = true
	} else {
		note(fmt.Sprintf("reindex-fail: %v", err))
	}

	// (b) XID wraparound — VACUUM (FREEZE, ANALYZE) when
	// MAX(age(datfrozenxid)) crosses 150M. Runs before the repack
	// gate so a failing stats read cannot skip it.
	m.xidFreezeCheck(ctx, pg, user, pass, res, note)

	// (c) sizes + dead-tuple estimate from pg_stat_user_tables.
	// Indexes via pg_indexes_size like the bash — total−heap would
	// count TOAST as index bytes.
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
	if !res.statsOK {
		// deadPct=0 + heapBytes=0 reads as "not bloated" — a failed
		// assessment must not skip repack and still report OK.
		res.okRepack = false
		res.repackState = "assess-fail"
		return
	}

	// (d) pg_repack ONLY when the heap is genuinely bloated —
	// autovacuum keeps it roughly compact, so this fires rarely.
	if res.deadPct <= m.d.Cfg.RepackDeadPct ||
		res.heapBytes <= m.d.Cfg.RepackMinHeapBytes {
		return
	}
	// W8-CP2 item 3: repack shadows the heap + WAL churn — require
	// free >= 2.5*(heap+wal) on the data fs first; otherwise run
	// only a VACUUM (ANALYZE) and warn (repack would fill the disk).
	free, wal, headroom := m.repackHeadroom(ctx, pg, user, pass,
		res.heapBytes, note)
	if !headroom {
		note(fmt.Sprintf("repack-skipped-insufficient-headroom (free=%dB heap=%dB wal=%dB)",
			free, res.heapBytes, wal))
		logger().Warn("kinedb: pg_repack skipped — insufficient disk headroom, VACUUM only",
			"free", free, "heap", res.heapBytes, "wal", wal)
		res.repackState = "skipped-headroom"
		if _, err := m.d.ExecLongEnv(ctx, kdeps.PsqlPassEnv(pass), m.d.PsqlArgs(pg, user, false,
			"-qc", "VACUUM (ANALYZE) "+kdeps.SQLIdent(m.d.Cfg.Table)), ""); err != nil {
			note(fmt.Sprintf("fallback-vacuum-fail: %v", err))
		}
		return
	}
	repackBin, rerr := m.d.Exec(ctx, []string{m.d.Cfg.Runtime, "exec", pg,
		"sh", "-c", repackGlob}, "")
	if rerr != nil {
		// A failed lookup reads identically to "no binary
		// installed" below — record which it was.
		note(fmt.Sprintf("repack-lookup-fail: %v", rerr))
	}
	repackBin = strings.TrimSpace(repackBin)
	if repackBin == "" {
		res.repackState = "no-binary"
		note(fmt.Sprintf(
			"repack-needed-no-binary (heap=%dB dead=%d%%)", res.heapBytes, res.deadPct))
		return
	}
	if _, err := m.d.ExecEnv(ctx, kdeps.PsqlPassEnv(pass), m.d.PsqlArgs(pg, user, false,
		"-qc", "CREATE EXTENSION IF NOT EXISTS pg_repack"), ""); err != nil {
		// pg_repack cannot run without the extension — attempting
		// it anyway fails identically and doubles the error noise.
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-ext-fail: %v", err))
		return
	}
	if _, err := m.d.ExecLongEnv(ctx, kdeps.PsqlPassEnv(pass), []string{m.d.Cfg.Runtime, "exec",
		"-e", "PGPASSWORD", pg, repackBin,
		"-h", "127.0.0.1", "-U", user, "-d", "postgres",
		"-t", "public." + m.d.Cfg.Table,
		"--no-superuser-check", "--no-order"}, ""); err == nil {
		res.repackState = "done"
	} else {
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-fail: %v", err))
	}
}

// reapInvalidIndexes — W12-CP2: drop the invalid index shells an
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
			if _, derr := m.d.ExecLongEnv(ctx, kdeps.PsqlPassEnv(pass), m.d.PsqlArgs(pg, user, false,
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
