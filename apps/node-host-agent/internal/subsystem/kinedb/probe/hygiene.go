// hygiene.go — the kine postgres hygiene block: the kine-pg-hygiene
// census and the postgres WAL archive guard, riding the 2-minute
// probe cycle (every input is a cheap pg_stat view — the heavy
// COUNT(*) stays in the guard cycle). Was wal_xid_hygiene.go minus
// the maint-cycle VACUUM (FREEZE) remediation, which moved to
// maint/freeze.go with the loop that owns it.
//
//  1. Idle-in-transaction census — sessions older than 3 minutes on
//     the postgres/kine databases pin snapshots and block autovacuum
//     of the kine table (Datadog/CERN class of apiserver OOM). The
//     gauge trips at 3min so the build-up is visible before the
//     5-minute session reaper in selfheal.go kills them.
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
//  7. Invalid-index census + seq-scan regression guard (invalid-index-reaper) —
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
//  8. Large-key census — the top-5 LIVE kine keys whose value
//     exceeds 512KiB (DISTINCT ON name ... ORDER BY name, id DESC
//     = kine's latest-revision read; deleted=0 keeps live keys).
//     The detoast of every live row's bytea is too heavy for every
//     probe round, so the scan rides a persisted 15m
//     last-kine-large-keys budget and the in-process cache
//     re-emits until the next window; exported as
//     kine_db_large_object_bytes{key="..."} — the per-key bloat
//     census behind the controller-side kine_large_objects audit.
//  9. backend_xmin horizon — MAX(age(backend_xmin)) per view
//     (pg_stat_activity + pg_stat_replication) exported as
//     kine_db_backend_xmin_age_transactions{source=...}: one hung
//     query/backup or a wedged hot-standby pinning an old xmin
//     blocks autovacuum's dead-tuple reclaim on kine while COMPACT
//     still succeeds — the leading edge of the index bloat the
//     maint cycle reindexes (hygiene_xmin.go).
//
// Items 5–6 export through their own textfile (kine-db-xact.prom)
// rather than emitProbe's kine-db.prom — the prometheus collector
// list lives in kdeps/probe.go outside this file, so the
// node-exporter textfile channel is the export path (the
// controllerhygiene textfile_prom convention).
//
// Per-concern halves live in the sibling hygiene_*.go files; this
// file keeps the shared result/const plumbing and the pgHygiene
// entrypoint that runs them in registration order.
package probe

import (
	"context"
	"time"
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

	// seqTupReadDeltaMax — invalid-index-reaper: tuples-read-by-seq-scan growth
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

	// Item 8 (kine-large-keys census): the top-5 live keys whose
	// value exceeds 512KiB — the per-key bloat census behind the
	// controller-side kine_large_objects audit. The DISTINCT ON
	// scan detoasts every live row's bytea, far too heavy for every
	// 2-minute probe round, so it rides a persisted 15m budget
	// (last-kine-large-keys, same spend-on-attempt contract as the
	// other last-* files) and the last census re-emits until the
	// next window — storelocal's maxObjBytes contract.
	largeKeysBudget  = 15 * time.Minute
	largeKeysFile    = "last-kine-large-keys"
	largeKeyMinBytes = 524288
	largeKeysTopN    = 5
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
	// Item 7 (invalid-index-reaper invalid-index census + seq-scan guard).
	invalidIdx   int64
	invalidSeen  bool
	seqScans     int64
	seqTupRead   int64
	seqSeen      bool
	analyzeFired bool // the seq-scan ANALYZE ran this round
	// Item 8 (kine-large-keys census — refreshed at most every
	// largeKeysBudget, re-emitted every round from the cache).
	largeKeys []largeKeyRow
	largeSeen bool
	// Item 9 (backend_xmin horizon — hygiene_xmin.go): the oldest
	// snapshot age per view; xminSeen gates the whole family (one
	// UNION ALL read answers both).
	xminActivity    int64
	xminReplication int64
	xminSeen        bool
}

// largeKeyRow is one census hit: the kine key path (name column —
// the full /registry/... key) and its live value's byte size.
type largeKeyRow struct {
	key   string
	bytes int64
}

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
// RunChecks only after containers+creds pass, so every query
// here can still assume a live postgres.
func (p *Probe) pgHygiene(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {
	h := &hygieneResult{}
	res.hyg = h
	p.hygieneIdleInTx(ctx, pg, user, pass, h, note)
	p.hygieneDeadTuple(ctx, pg, user, pass, h, note)
	p.hygieneXID(ctx, pg, user, pass, h, note)
	p.hygieneWAL(ctx, pg, user, pass, h, note)
	p.hygieneCatalog(ctx, pg, user, pass, h, note)
	p.hygienePreparedXacts(ctx, pg, user, pass, h, note)
	p.hygieneSeqScan(ctx, pg, user, pass, h, note)
	p.hygieneLargeKeys(ctx, pg, user, pass, h, note)
	p.hygieneBackendXmin(ctx, pg, user, pass, h, note)
	p.emitXactTextfile(h)
}
