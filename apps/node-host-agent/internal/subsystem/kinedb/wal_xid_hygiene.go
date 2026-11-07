// wal_xid_hygiene.go — the kine postgres hygiene block: the
// kine-pg-hygiene census and the postgres WAL archive guard, riding
// the 2-minute probe cycle (every input is a cheap pg_stat view —
// the heavy COUNT(*) stays in the guard cycle).
//
//  1. Idle-in-transaction census — sessions older than 3 minutes on
//     the postgres/kine databases pin snapshots and block autovacuum
//     of the kine table (Datadog/CERN class of apiserver OOM). The
//     gauge trips at 3min so the build-up is visible before the
//     5-minute session reaper in kine_self_healing.go kills them.
//  2. Dead-tuple ratio — n_dead_tup/GREATEST(n_live_tup,1) of the
//     kine table. Above 0.50 with >50K dead tuples autovacuum has
//     clearly lost the race → an advisory-locked VACUUM (ANALYZE)
//     under the 30m last-dead-tuple-vacuum budget: the same lock
//     the compact guard takes (a running compact already ends in
//     VACUUM), the same last-* rate budget shape as last-pgb-restart,
//     so the probe cadence cannot spam vacuum workers.
//  3. XID wraparound — MAX(age(datfrozenxid)) feeds
//     kine_db_xid_age_transactions every probe round; the
//     remediation (VACUUM (FREEZE, ANALYZE) past 150M) runs in the
//     daily maint cycle so the freeze storm lands inside the window
//     that already serialises REINDEX/repack.
//  4. WAL archive guard — pg_ls_waldir bytes, WAL as a fraction of
//     the data filesystem, pg_stat_archiver continuous-failure
//     staleness (>30m), and inactive replication-slot retention. A
//     dead slot pins every WAL segment since restart_lsn — the
//     classic way a postgres data disk fills to PANIC; past the
//     10GiB critical threshold the orphan slot is dropped (5GiB only
//     notes a warning).
//  5. MultiXact age — MAX(age(datminmxid)) feeds
//     kine_db_multixact_age_transactions: the row-lock-share
//     wraparound horizon, the lesser-known twin of the datfrozenxid
//     wraparound item 3 watches.
//  6. Orphaned prepared transactions — pg_prepared_xacts rows on the
//     postgres/kine databases older than 15min. A prepared xact
//     whose coordinator vanished holds its xmin open forever —
//     pinning the xmin horizon exactly like an idle-in-transaction
//     session but invisible to pg_stat_activity — so the probe both
//     gauges them (kine_db_orphan_prepared_xacts) and rolls them
//     back automatically (ROLLBACK PREPARED), counting releases in
//     kine_db_orphan_prepared_xacts_rolled_back_total.
//  7. Invalid-index census + seq-scan regression guard (W12-CP2) —
//     kine_db_invalid_indexes counts pg_index rows with
//     indisvalid=false (dead *_ccnew/*_ccold shells an interrupted
//     REINDEX CONCURRENTLY leaves behind — they cost every INSERT
//     but serve no query; the drop itself is the maint cycle's
//     reaper). kine_db_seq_scans_total/kine_db_seq_tuples_read_total
//     track the kine table's seq-scan counters — a seq_tup_read
//     delta >500K between probes means the planner fell back to a
//     sequential scan (stale pg_statistic or a poisoned index), so
//     an ANALYZE runs immediately under the 30m last-kine-analyze
//     budget instead of waiting for the daily maint window.
//
// Items 5–6 export through their own textfile (kine-db-xact.prom)
// rather than emitProbe's kine-db.prom — the prometheus collector
// list lives in kinedb.go/probe.go outside this file, so the
// node-exporter textfile channel is the export path (the
// controllerhygiene textfile_prom convention).
package kinedb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

const (
	// deadTupleVacuumBudget — the last-dead-tuple-vacuum cooldown
	// file under GuardStateDir: a just-attempted emergency vacuum
	// must not re-fire every probe round.
	deadTupleVacuumBudget = 30 * time.Minute
	deadTupleVacuumFile   = "last-dead-tuple-vacuum"

	// deadTupleRatioMax / deadTupleMinCount — the emergency vacuum
	// gate. The absolute floor matters: a ratio alone false-positives
	// on a near-empty table (one dead tuple out of two rows = 0.5).
	deadTupleRatioMax = 0.50
	deadTupleMinCount = 50000

	// xidFreezeAge — MAX(age(datfrozenxid)) past which the maint
	// cycle forces VACUUM (FREEZE, ANALYZE): ~7% of the 2^31
	// wraparound horizon, far ahead of the autovacuum-freeze panic
	// zone yet early enough that the freeze storm finishes in the
	// daily window.
	xidFreezeAge = 150_000_000

	// slotRetainedWarn / slotRetainedDrop — WAL bytes an inactive
	// replication slot may pin before the guard reacts. Warn only
	// notes; drop runs pg_drop_replication_slot — a consumer dead
	// long enough to hold >10GiB will never catch up, and the
	// alternative is a full pg_wal → PANIC on the DB VM.
	slotRetainedWarn = 5 << 30
	slotRetainedDrop = 10 << 30

	// archiveStaleSecs — a failed archive attempt newer than the
	// last success only counts as CONTINUOUSLY failing once the last
	// success is this old (seconds).
	archiveStaleSecs = 1800

	// seqTupReadDeltaMax — W12-CP2: tuples-read-by-seq-scan growth
	// between probe rounds that marks a planner regression to
	// sequential scan (the kine table is supposed to answer
	// LIST/WATCH via kine_name_prev_revision_uindex / kine_id_idx).
	seqTupReadDeltaMax = 500_000
	// seqTupReadFile keeps the previous round's seq_tup_read under
	// GuardStateDir — the delta must survive an agent restart.
	seqTupReadFile = "last-seq-tup-read"
	// kineAnalyzeBudget/kineAnalyzeFile — the 30m last-kine-analyze
	// cooldown on the immediate ANALYZE a seq-scan regression
	// triggers; same last-* spend-on-attempt contract as
	// last-dead-tuple-vacuum.
	kineAnalyzeBudget = 30 * time.Minute
	kineAnalyzeFile   = "last-kine-analyze"
)

// inactiveSlot is one pg_replication_slots row with active=false.
type inactiveSlot struct {
	name     string
	retained int64 // WAL bytes pinned since restart_lsn
}

// hygieneResult captures one probe-cycle hygiene read for emission
// + tests — every field behind a *Seen flag so a failed query gates
// its series out instead of fabricating a zero over a real value.
type hygieneResult struct {
	idleInTx     int64
	idleSeen     bool
	deadRatio    float64
	deadTup      int64
	deadSeen     bool
	vacuumFired  bool
	xidAge       int64
	xidSeen      bool
	walBytes     int64
	walSeen      bool
	walDiskRatio float64
	walDiskSeen  bool
	archiveStale int64
	archiveSeen  bool
	slotRetained int64
	slotSeen     bool
	slotsDropped int64
	// Items 5–6 (multiXact horizon + orphan prepared xacts).
	mxidAge        int64
	mxidSeen       bool
	preparedXacts  int64
	preparedSeen   bool
	preparedRolled int64 // rolled back THIS round
	// Item 7 (W12-CP2 invalid-index census + seq-scan guard).
	invalidIdx   int64
	invalidSeen  bool
	seqScans     int64
	seqTupRead   int64
	seqSeen      bool
	analyzeFired bool // the seq-scan ANALYZE ran this round
}

// preparedXactRolledBackTotal is the lifetime count behind
// kine_db_orphan_prepared_xacts_rolled_back_total — in-process
// cumulative like metrics.idleTermTotal (a prometheus Counter
// resets on restart anyway; the textfile emits the running total
// every round the block runs).
var preparedXactRolledBackTotal atomic.Int64

// preparedXactOrphanAge — a prepared transaction still listed in
// pg_prepared_xacts past this age counts as orphaned: its
// coordinator had every chance to COMMIT/ABORT PREPARED, so what
// remains pins the xmin horizon with nobody left to finish it.
const preparedXactOrphanAge = "15 minutes"

// xactPromFile is the textfile items 5–6 export through — kept
// separate from emitProbe's kine-db.prom because that render is
// owned by probe.go (a second writer would just be overwritten each
// round, and duplicate series across textfiles fail the scrape).
const xactPromFile = "kine-db-xact.prom"

// pgHygiene runs the whole hygiene block once — called from
// runProbeChecks only after containers+creds pass, so every query
// here can still assume a live postgres.
func (k *KineDB) pgHygiene(ctx context.Context, pg, user, pass string,
	res *probeResult, note func(string)) {
	h := &hygieneResult{}
	res.hyg = h
	k.hygieneIdleInTx(ctx, pg, user, pass, h, note)
	k.hygieneDeadTuple(ctx, pg, user, pass, h, note)
	k.hygieneXID(ctx, pg, user, pass, h, note)
	k.hygieneWAL(ctx, pg, user, pass, h, note)
	k.hygieneMultiXact(ctx, pg, user, pass, h, note)
	k.hygienePreparedXacts(ctx, pg, user, pass, h, note)
	k.hygieneInvalidIndexes(ctx, pg, user, pass, h, note)
	k.hygieneSeqScan(ctx, pg, user, pass, h, note)
	k.emitXactTextfile(h)
}

// hygieneMultiXact — item 5: MAX(age(datminmxid)) across databases.
// MultiXact IDs are consumed by row-level SHARE locks (foreign keys
// checking referenced rows); exhaustion forces the same emergency
// freeze cycle as XID wraparound, so the gauge rides the same
// 2-minute freshness as kine_db_xid_age_transactions.
func (k *KineDB) hygieneMultiXact(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datminmxid)),0) FROM pg_database")
	if err != nil {
		note(fmt.Sprintf("mxid-age-fail: %v", err))
		return
	}
	v, perr := strconv.ParseInt(firstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("mxid-age-unparsed: %v", perr))
		return
	}
	h.mxidAge, h.mxidSeen = v, true
}

// hygienePreparedXacts — item 6: prepared transactions orphaned past
// preparedXactOrphanAge on the postgres/kine databases, rolled back
// in place. ROLLBACK PREPARED is the safe release: the coordinator
// is gone by definition (an alive one commits/aborts itself long
// before 15min), and ABORT is the conservative half of the outcome
// — no data commit happens, only the xmin pin releases. A failed
// rollback is noted and retried next round, never fatal.
func (k *KineDB) hygienePreparedXacts(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT gid FROM pg_prepared_xacts "+
			"WHERE database IN ('postgres','kine') "+
			"AND prepared < now() - interval '%s'", preparedXactOrphanAge))
	if err != nil {
		note(fmt.Sprintf("prepared-xacts-fail: %v", err))
		return
	}
	h.preparedSeen = true // a successful empty read = no orphans
	for _, gid := range parseGIDs(out) {
		h.preparedXacts++
		if k.cfg.ReadOnly {
			continue // diagnostics only — no ROLLBACK PREPARED
		}
		if _, rerr := k.psqlQuery(ctx, pg, user, pass,
			"ROLLBACK PREPARED "+sqlQuote(gid)); rerr != nil {
			note(fmt.Sprintf("rollback-prepared-%s-fail: %v", gid, rerr))
			continue
		}
		h.preparedRolled++
		preparedXactRolledBackTotal.Add(1)
		logger().Warn("kinedb: rolled back orphaned prepared transaction",
			"gid", gid)
	}
	if k.cfg.ReadOnly && h.preparedXacts > 0 {
		note(fmt.Sprintf("read-only: %d orphaned prepared xact(s) left in place",
			h.preparedXacts))
	}
}

// hygieneInvalidIndexes — item 7a (W12-CP2): indexes with
// indisvalid=false across pg_index. An invalid index is dead
// weight — every INSERT still maintains it but the planner never
// uses it, and the next REINDEX CONCURRENTLY errors or silently
// leaves it. The probe only counts (kine_db_invalid_indexes feeds
// the alert); the DROP itself belongs to the maint cycle's
// invalid-index reaper (maint.go) where the daily serialisation
// already gates the index churn.
// COUNT(indexrelid), not COUNT(*): the probe contract bans a bare
// COUNT(*) in the 2-minute loop — counting a catalog column is
// semantically identical and keeps the kine-heap seq-scan guard
// (probe_test.go) airtight.
func (k *KineDB) hygieneInvalidIndexes(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COUNT(indexrelid) FROM pg_index WHERE NOT indisvalid")
	if err != nil {
		note(fmt.Sprintf("invalid-indexes-fail: %v", err))
		return
	}
	v, perr := strconv.ParseInt(firstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("invalid-indexes-unparsed: %v", perr))
		return
	}
	h.invalidIdx, h.invalidSeen = v, true
}

// hygieneSeqScan — item 7b (W12-CP2): seq_scan / seq_tup_read of the
// kine table from pg_stat_user_tables. A planner regression to
// sequential scan (stale statistics after a churn burst, or a
// poisoned index) shows as a seq_tup_read spike BEFORE the CPU
// storm makes apiserver LIST/WATCH time out — the Datadog/Rancher
// k3s failure mode. Past seqTupReadDeltaMax between probes the
// planner stats get refreshed immediately: ANALYZE under the 30m
// last-kine-analyze budget (spend-on-attempt, same contract as
// last-dead-tuple-vacuum).
func (k *KineDB) hygieneSeqScan(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE(seq_scan,0), COALESCE(seq_tup_read,0) "+
			"FROM pg_stat_user_tables WHERE relname=%s", sqlQuote(k.cfg.Table)))
	if err != nil {
		note(fmt.Sprintf("seq-scan-fail: %v", err))
		return
	}
	scans, tupRead, perr := parsePair(out)
	if perr != nil {
		// An empty result means the stats view has no row for the
		// table yet — inconclusive, like a parse failure.
		note(fmt.Sprintf("seq-scan-unparsed: %v", perr))
		return
	}
	h.seqScans, h.seqTupRead, h.seqSeen = scans, tupRead, true

	// Delta vs the previous probe — persisted under GuardStateDir
	// so the guard survives an agent restart. A pg_stat reset (DB
	// restart) reads as a negative delta and simply re-baselines.
	prevPath := filepath.Join(k.cfg.GuardStateDir, seqTupReadFile)
	prev, perr := readIntFile(prevPath)
	if k.cfg.ReadOnly {
		// Diagnostics only — never the baseline write, the
		// ANALYZE, or the last-kine-analyze budget spend.
		return
	}
	writeIntFile(prevPath, tupRead)
	if perr != nil {
		// First observation (or an unreadable baseline): the
		// lifetime seq_tup_read is NOT a delta — seed prev with the
		// current value and skip, or the first probe after every
		// agent restart fires a bogus ANALYZE.
		return
	}
	delta := tupRead - prev
	if delta <= seqTupReadDeltaMax {
		return
	}
	note(fmt.Sprintf("seq-tup-read +%d>%d between probes — planner fell back to seq scan; ANALYZE %s",
		delta, seqTupReadDeltaMax, k.cfg.Table))
	// MkdirAll before the spend — Store.WriteEpochFile does not
	// create the state dir itself (same note as deadTupleVacuum).
	_ = os.MkdirAll(k.cfg.GuardStateDir, 0o755)
	if !k.state.RateTrySpend(kineAnalyzeFile, kineAnalyzeBudget) {
		note("kine-analyze cooldown (<30m)")
		return
	}
	if _, aerr := k.execLongEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false,
		"-qc", "ANALYZE "+sqlIdent(k.cfg.Table)), ""); aerr != nil {
		note(fmt.Sprintf("kine-analyze-fail: %v", aerr))
		return
	}
	h.analyzeFired = true
	logger().Warn("kinedb: seq-scan regression — ran ANALYZE",
		"table", k.cfg.Table, "seq_tup_read_delta", delta)
}

// parseGIDs splits the gid list of the prepared-xacts query — one
// identifier per -tA line; empty/blank lines are skipped.
func parseGIDs(out string) []string {
	var gids []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		gids = append(gids, l)
	}
	return gids
}

// emitXactTextfile renders kine-db-xact.prom for items 5–6 — header
// always, sample only behind its *Seen flag (a failed read goes
// absent rather than fabricating a zero), and the lifetime rollback
// counter every round like idleTermTotal.
func (k *KineDB) emitXactTextfile(h *hygieneResult) {
	if k.cfg.ReadOnly {
		// A zeroed in-process counter would overwrite the daemon's
		// series — read-only mode never writes textfiles.
		return
	}
	var p promfile.Builder
	mxidHelp := "MAX(age(datminmxid)) across databases — distance " +
		"to MultiXact wraparound pressure."
	if h.mxidSeen {
		p.Gauge("kine_db_multixact_age_transactions", mxidHelp,
			float64(h.mxidAge))
	} else {
		p.Header("kine_db_multixact_age_transactions", mxidHelp)
	}
	preparedHelp := "Prepared transactions older than " +
		preparedXactOrphanAge + " on the postgres/kine databases — " +
		"orphaned xacts pinning the xmin horizon."
	if h.preparedSeen {
		p.Gauge("kine_db_orphan_prepared_xacts", preparedHelp,
			float64(h.preparedXacts))
	} else {
		p.Header("kine_db_orphan_prepared_xacts", preparedHelp)
	}
	p.HeaderType("kine_db_orphan_prepared_xacts_rolled_back_total",
		"Orphaned prepared transactions rolled back by the agent "+
			"(ROLLBACK PREPARED) to release the xmin horizon.", "counter")
	p.Line(fmt.Sprintf("kine_db_orphan_prepared_xacts_rolled_back_total %d",
		preparedXactRolledBackTotal.Load()))
	k.emitTextfile(xactPromFile, &p)
}

// hygieneIdleInTx — item 1: sessions idle-in-transaction >3min on
// the postgres/kine databases. COUNT(pid) rather than COUNT(*): the
// probe contract bans a bare COUNT(*) in the 2-minute loop (the
// tests guard against the kine heap seq-scan creeping back), and
// counting a NOT NULL column is identical semantics on a stats view.
func (k *KineDB) hygieneIdleInTx(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COUNT(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') "+
			"AND state = 'idle in transaction' "+
			"AND state_change < now() - interval '3 minutes'")
	if err != nil {
		note(fmt.Sprintf("idle-tx-fail: %v", err))
		return
	}
	v, perr := strconv.ParseInt(firstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("idle-tx-unparsed: %v", perr))
		return
	}
	h.idleInTx, h.idleSeen = v, true
}

// hygieneDeadTuple — item 2: dead-tuple ratio plus the emergency
// VACUUM trigger when autovacuum is visibly losing.
func (k *KineDB) hygieneDeadTuple(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT n_dead_tup, n_live_tup FROM pg_stat_user_tables "+
			"WHERE relname=%s", sqlQuote(k.cfg.Table)))
	if err != nil {
		note(fmt.Sprintf("dead-tuple-fail: %v", err))
		return
	}
	dead, live, perr := parsePair(out)
	if perr != nil {
		// An empty result means the stats view has no row for the
		// table yet — inconclusive, like a parse failure.
		note(fmt.Sprintf("dead-tuple-unparsed: %v", perr))
		return
	}
	h.deadTup, h.deadSeen = dead, true
	h.deadRatio = float64(dead) / float64(max(live, 1))
	if h.deadRatio <= deadTupleRatioMax || dead <= deadTupleMinCount {
		return
	}
	if k.cfg.ReadOnly {
		note(fmt.Sprintf("read-only: dead-tuple VACUUM (ANALYZE) suppressed (dead=%d ratio=%.2f)",
			dead, h.deadRatio))
		return
	}
	if k.deadTupleVacuum(ctx, pg, user, pass, note) {
		h.vacuumFired = true
		logger().Warn("kinedb: emergency dead-tuple VACUUM (ANALYZE)",
			"table", k.cfg.Table, "dead_tup", dead, "ratio", h.deadRatio)
	}
}

// deadTupleVacuum runs VACUUM (ANALYZE) inside a single psql session
// gated by the compact guard's advisory lock — a busy lock means a
// compact session (which ends in VACUUM anyway) is running, so skip
// instead of queueing. The RateTrySpend lands on the ATTEMPT like
// the pgb-restart budget: a failing vacuum does not retry every
// probe round.
func (k *KineDB) deadTupleVacuum(ctx context.Context, pg, user, pass string,
	note func(string)) bool {
	// MkdirAll before the spend — Store.WriteEpochFile does not
	// create the state dir itself (same note as checkPGBWedge).
	_ = os.MkdirAll(k.cfg.GuardStateDir, 0o755)
	if !k.state.RateTrySpend(deadTupleVacuumFile, deadTupleVacuumBudget) {
		note("dead-tuple-vacuum-cooldown (<30m)")
		return false
	}
	var b strings.Builder
	fmt.Fprintf(&b,
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS kh_locked;\n",
		k.cfg.AdvisoryLockID)
	b.WriteString("\\gset\n\\if :kh_locked\n")
	fmt.Fprintf(&b, "VACUUM (ANALYZE) %s;\n", sqlIdent(k.cfg.Table))
	fmt.Fprintf(&b, "SELECT pg_advisory_unlock(%d);\n", k.cfg.AdvisoryLockID)
	b.WriteString("\\else\n\\echo '" + lockBusyMarker + "'\n\\endif\n")
	sout, err := k.psqlScript(ctx, pg, user, pass, b.String())
	switch {
	case err != nil:
		note(fmt.Sprintf("dead-tuple-vacuum-fail: %v", err))
	case strings.Contains(sout, lockBusyMarker):
		note("dead-tuple-vacuum lock busy (compact running)")
	default:
		return true
	}
	return false
}

// hygieneXID — item 3: MAX(age(datfrozenxid)) across databases. Only
// the gauge lives here; the VACUUM (FREEZE, ANALYZE) remediation is
// xidFreezeCheck in the maint cycle.
func (k *KineDB) hygieneXID(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database")
	if err != nil {
		note(fmt.Sprintf("xid-age-fail: %v", err))
		return
	}
	v, perr := strconv.ParseInt(firstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("xid-age-unparsed: %v", perr))
		return
	}
	h.xidAge, h.xidSeen = v, true
}

// hygieneWAL — item 4: pg_wal size, wal/datafs ratio, archiver
// staleness and inactive-slot retention (with the orphan-slot drop).
func (k *KineDB) hygieneWAL(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {

	// (a) total WAL bytes — same pg_ls_waldir read repackHeadroom does.
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE((SELECT SUM(size) FROM pg_ls_waldir()),0)")
	if err != nil {
		note(fmt.Sprintf("wal-size-fail: %v", err))
	} else if wal, perr := strconv.ParseInt(firstLine(out), 10, 64); perr != nil {
		note(fmt.Sprintf("wal-size-unparsed: %v", perr))
	} else {
		h.walBytes, h.walSeen = wal, true
	}

	// (b) WAL as a fraction of the data filesystem capacity —
	// --output=size (total, not avail: the ratio measures retention
	// pressure, not remaining headroom). Only meaningful when the
	// WAL read succeeded.
	if h.walSeen {
		dataDir := k.cfg.PGDataDir
		if dataDir == "" {
			dataDir = defaultPGDataDir
		}
		df, derr := k.exec(ctx, []string{k.cfg.Runtime, "exec", pg,
			"df", "-B1", "--output=size", dataDir}, "")
		if derr != nil {
			note(fmt.Sprintf("wal-df-fail: %v", derr))
		} else {
			var lastLine string
			for _, l := range strings.Split(strings.TrimSpace(df), "\n") {
				lastLine = strings.TrimSpace(l)
			}
			if size, perr := strconv.ParseInt(lastLine, 10, 64); perr != nil {
				note(fmt.Sprintf("wal-df-unparsed: %v", perr))
			} else if size > 0 {
				h.walDiskRatio = float64(h.walBytes) / float64(size)
				h.walDiskSeen = true
			}
		}
	}

	// (c) archiver staleness — a failed attempt newer than the last
	// success is "failing"; it only counts as STALE once the last
	// success (or, when it never archived, the stats reset) is >30m
	// old. A recent failure that then succeeded reads clean.
	out, err = k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT CASE WHEN failed_count > 0 "+
			"AND last_failed_time > COALESCE(last_archived_time, '-infinity'::timestamptz) "+
			"AND EXTRACT(EPOCH FROM now() - COALESCE(last_archived_time, stats_reset)) > %d "+
			"THEN 1 ELSE 0 END FROM pg_stat_archiver", archiveStaleSecs))
	if err != nil {
		note(fmt.Sprintf("archiver-fail: %v", err))
	} else if v, perr := strconv.ParseInt(firstLine(out), 10, 64); perr != nil {
		note(fmt.Sprintf("archiver-unparsed: %v", perr))
	} else {
		h.archiveStale, h.archiveSeen = v, true
	}

	// (d) inactive replication slots — retained WAL since restart_lsn.
	out, err = k.psqlQuery(ctx, pg, user, pass,
		"SELECT slot_name, "+
			"COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn),0)::bigint "+
			"FROM pg_replication_slots WHERE NOT active")
	if err != nil {
		note(fmt.Sprintf("slots-fail: %v", err))
		return
	}
	h.slotSeen = true // a successful empty read = no inactive slots
	for _, s := range parseSlotRows(out) {
		h.slotRetained += s.retained
		switch {
		case s.retained > slotRetainedDrop:
			// Past the critical threshold the slot is an orphan
			// pinning the disk to PANIC — drop it and let the
			// consumer resync from scratch if it ever returns.
			if k.cfg.ReadOnly {
				note(fmt.Sprintf("read-only: inactive slot %s pins %dB WAL (>%dGiB) — drop suppressed",
					s.name, s.retained, slotRetainedDrop>>30))
				continue
			}
			note(fmt.Sprintf("inactive slot %s pins %dB WAL (>%dGiB) — dropping",
				s.name, s.retained, slotRetainedDrop>>30))
			if _, derr := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
				"SELECT pg_drop_replication_slot(%s)", sqlQuote(s.name))); derr != nil {
				note(fmt.Sprintf("drop-slot-%s-fail: %v", s.name, derr))
			} else {
				h.slotsDropped++
				logger().Warn("kinedb: dropped inactive replication slot",
					"slot", s.name, "retained_bytes", s.retained)
			}
		case s.retained > slotRetainedWarn:
			note(fmt.Sprintf("inactive slot %s pins %dB WAL (>%dGiB)",
				s.name, s.retained, slotRetainedWarn>>30))
		}
	}
}

// parseSlotRows parses the `name|bytes` rows of the inactive-slot
// query — unparseable lines are skipped, never fatal.
func parseSlotRows(out string) []inactiveSlot {
	var slots []inactiveSlot
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		f := strings.SplitN(l, "|", 2)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
		if err != nil {
			continue
		}
		slots = append(slots, inactiveSlot{
			name: strings.TrimSpace(f[0]), retained: v})
	}
	return slots
}

// sqlQuote wraps s as a single-quoted SQL literal — slot names come
// back from the server rather than user input, but a stray quote in
// the name must still not break the DROP statement.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sqlIdent wraps s as a double-quoted SQL identifier — cfg.Table is
// validated as a plain identifier by applyDefaults, but it lands in
// DDL positions (VACUUM/REINDEX/FROM/UPDATE) where sqlQuote's string
// literal would be wrong; quoting keeps the interpolation safe even
// if a name ever bypasses the config check.
func sqlIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// xidFreezeCheck is the maint-cycle half of item 3: the probe owns
// the kine_db_xid_age_transactions series (2-minute freshness); the
// freeze remediation runs here where the daily cadence already
// serialises the heavy reindex/repack work — a FREEZE vacuum is a
// full-table rewrite freeze storm, not a probe-time action.
func (k *KineDB) xidFreezeCheck(ctx context.Context, pg, user, pass string,
	res *maintResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database")
	if err != nil {
		note(fmt.Sprintf("xid-age-fail: %v", err))
		return
	}
	age, perr := strconv.ParseInt(firstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("xid-age-unparsed: %v", perr))
		return
	}
	res.xidAge, res.xidSeen = age, true
	res.freezeState = "skipped"
	k.m.xidAge.Set(float64(age))
	if age <= xidFreezeAge {
		return
	}
	note(fmt.Sprintf("xid-age=%d>%d — VACUUM (FREEZE, ANALYZE)", age, xidFreezeAge))
	logger().Warn("kinedb: XID age past freeze threshold — VACUUM (FREEZE, ANALYZE)",
		"xid_age", age, "threshold", xidFreezeAge)
	if _, verr := k.execLongEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false,
		"-qc", "VACUUM (FREEZE, ANALYZE) "+sqlIdent(k.cfg.Table)), ""); verr != nil {
		res.okFreeze = false
		res.freezeState = "fail"
		note(fmt.Sprintf("freeze-vacuum-fail: %v", verr))
		return
	}
	res.freezeState = "done"
}
