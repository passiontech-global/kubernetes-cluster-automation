// maint.go — the daily maintenance job (kine-db-maint.sh port).
//
// Why it exists (incident 2026-09-28): the kine table's index bloat
// made `SELECT MAX(id)` take seconds, pushing kine init past the k0s
// health-check window and crash-looping remote controllers.
// autovacuum only reclaims dead tuples — it never reindexes and never
// shrinks the heap — so this job runs:
//
//	reindex  REINDEX TABLE CONCURRENTLY kine — always (cheap on a
//	         small table, SHARE UPDATE EXCLUSIVE lock)
//	repack   pg_repack --no-superuser-check --no-order -t public.kine
//	         — ONLY when the heap is genuinely bloated
//	         (dead_tuple_percent > 40 AND heap > 200MB, measured via
//	         pg_stat_user_tables + pg_relation_size). Online shadow
//	         copy, needs ~2x table space transiently.
package kinedb

import (
	"context"
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
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

// maintResult captures one maintenance run for emission + tests.
type maintResult struct {
	okReindex   bool
	okRepack    bool   // skip counts as ok — a ran-and-failed repack (or a failed assessment) flips it
	repackState string // skipped|done|fail|no-binary|assess-fail
	heapBytes   int64
	indexBytes  int64
	deadPct     int64
	statsOK     bool // sizes/dead-tuple stats were actually read this run
	notes       []string
}

// maintCycle runs one maintenance round and emits metrics +
// textfile. Returns the result for tests.
func (k *KineDB) maintCycle(ctx context.Context) *maintResult {
	res := &maintResult{okRepack: true, repackState: "skipped"}
	note := func(s string) { res.notes = append(res.notes, s) }

	user, pass, credOK := k.creds()
	pg := k.pgContainerName(ctx)
	switch {
	case !credOK:
		note(fmt.Sprintf("missing .env creds (%s)", k.cfg.EnvFile))
	case !k.containerRunning(ctx, pg):
		note(fmt.Sprintf("postgres container %s down", pg))
	default:
		k.maintRun(ctx, pg, user, pass, res, note)
	}
	k.emitMaint(res)
	sum := fmt.Sprintf("reindex=%v repack=%s heap=%dB idx=%dB dead=%d%%",
		res.okReindex, res.repackState, res.heapBytes, res.indexBytes, res.deadPct)
	if res.okReindex && res.okRepack {
		logger().Info("kine-db-maint OK: " + sum)
		k.m.cycles.WithLabelValues("maint", "ok").Inc()
	} else {
		logger().Warn("kine-db-maint FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		k.m.cycles.WithLabelValues("maint", "fail").Inc()
	}
	return res
}

func (k *KineDB) maintRun(ctx context.Context, pg, user, pass string,
	res *maintResult, note func(string)) {

	// (a) REINDEX CONCURRENTLY — always, cheap on a small table.
	if _, err := k.execLong(ctx, k.psqlArgs(pg, user, pass, false,
		"-qc", "REINDEX TABLE CONCURRENTLY "+k.cfg.Table), ""); err == nil {
		res.okReindex = true
	} else {
		note(fmt.Sprintf("reindex-fail: %v", err))
	}

	// (b) sizes + dead-tuple estimate from pg_stat_user_tables.
	// Indexes via pg_indexes_size like the bash — total−heap would
	// count TOAST as index bytes.
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT pg_relation_size('%s'), pg_indexes_size('%[1]s'), "+
			"COALESCE((SELECT n_dead_tup FROM pg_stat_user_tables WHERE relname='%[1]s'),0), "+
			"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname='%[1]s'),0)",
		k.cfg.Table))
	if err == nil {
		heap, idx, dead, live, perr := parseQuad(out)
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

	// (c) pg_repack ONLY when the heap is genuinely bloated —
	// autovacuum keeps it roughly compact, so this fires rarely.
	if res.deadPct <= k.cfg.RepackDeadPct ||
		res.heapBytes <= k.cfg.RepackMinHeapBytes {
		return
	}
	// W8-CP2 item 3: repack shadows the heap + WAL churn — require
	// free >= 2.5*(heap+wal) on the data fs first; otherwise run
	// only a VACUUM (ANALYZE) and warn (repack would fill the disk).
	free, wal, headroom := k.repackHeadroom(ctx, pg, user, pass,
		res.heapBytes, note)
	if !headroom {
		note(fmt.Sprintf("repack-skipped-insufficient-headroom (free=%dB heap=%dB wal=%dB)",
			free, res.heapBytes, wal))
		logger().Warn("kinedb: pg_repack skipped — insufficient disk headroom, VACUUM only",
			"free", free, "heap", res.heapBytes, "wal", wal)
		res.repackState = "skipped-headroom"
		if _, err := k.execLong(ctx, k.psqlArgs(pg, user, pass, false,
			"-qc", "VACUUM (ANALYZE) "+k.cfg.Table), ""); err != nil {
			note(fmt.Sprintf("fallback-vacuum-fail: %v", err))
		}
		return
	}
	repackBin, rerr := k.exec(ctx, []string{k.cfg.Runtime, "exec", pg,
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
	if _, err := k.exec(ctx, k.psqlArgs(pg, user, pass, false,
		"-qc", "CREATE EXTENSION IF NOT EXISTS pg_repack"), ""); err != nil {
		// pg_repack cannot run without the extension — attempting
		// it anyway fails identically and doubles the error noise.
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-ext-fail: %v", err))
		return
	}
	if _, err := k.execLong(ctx, []string{k.cfg.Runtime, "exec",
		"-e", "PGPASSWORD=" + pass, pg, repackBin,
		"-h", "127.0.0.1", "-U", user, "-d", "postgres",
		"-t", "public." + k.cfg.Table,
		"--no-superuser-check", "--no-order"}, ""); err == nil {
		res.repackState = "done"
	} else {
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-fail: %v", err))
	}
}

// emitMaint renders the textfile and updates the collectors.
func (k *KineDB) emitMaint(res *maintResult) {
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
	k.m.maintOK.WithLabelValues("reindex").Set(reindex)
	k.m.maintOK.WithLabelValues("repack").Set(repack)
	ts := float64(k.cfg.nowFn().Unix())
	p.Gauge("kine_db_maint_last_run_timestamp_seconds",
		"Last maintenance run", ts)
	k.m.maintLastRun.Set(ts)
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
		k.m.maintRelBytes.WithLabelValues("heap").Set(float64(res.heapBytes))
		k.m.maintRelBytes.WithLabelValues("indexes").Set(float64(res.indexBytes))
	}
	k.emitTextfile("kine-db-maint.prom", &p)
}
