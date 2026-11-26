// batch.go — Wave-4 read-only psql batching for the 2-minute probe
// round: merges the six unconditional post-auth read-only queries
// (revision_horizon, hygieneScalarStats, hygieneWAL inactive slots,
// hygieneCatalog, hygienePreparedXacts, hygieneBackendXmin) into ONE
// tagged PsqlQuery alongside `select 1` (CheckBackendEnv), cutting
// steady-state direct-to-postgres execs from 7 to 2 per round.
package probe

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// probeBatch holds the parsed tagged rows from one batched read-only
// PsqlQuery (or the exec error if the batch failed).
type probeBatch struct {
	err     error
	hasTags bool

	revLine string
	revSeen bool

	idleLine string
	idleSeen bool
	deadLine string
	deadSeen bool
	xidLine  string
	xidSeen  bool
	walLine  string
	walSeen  bool
	archLine string
	archSeen bool

	slotLines []string
	slotsSeen bool

	mxidLine     string
	mxidSeen     bool
	invidxLine   string
	invidxSeen   bool
	seqLine      string
	seqSeen      bool
	idtypeLine   string
	idtypeSeen   bool
	seqcliffLine string
	seqcliffSeen bool

	pxLines []string
	pxSeen  bool

	xminLines []string
	xminSeen  bool
}

func probeBatchSQL(table string) string {
	tblIdent := kdeps.SQLIdent(table)
	tblQ := kdeps.SQLQuote(table)
	seqByOID := "(SELECT c.relname FROM pg_class c WHERE c.oid = " +
		"pg_get_serial_sequence(" + tblQ + ", 'id')::regclass)"
	seqFallbackQ := kdeps.SQLQuote(table + "_id_seq")
	seqNameExpr := "COALESCE(" + seqByOID + ", " + seqFallbackQ + ")"
	return "SELECT 'rev', COALESCE((SELECT MAX(id) FROM " + tblIdent + "),0), " +
		"COALESCE((SELECT MAX(prev_revision) FROM " + tblIdent + " WHERE name=" + kdeps.SQLQuote(kdeps.CompactRevKey) + "),0), " +
		"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname=" + tblQ + "),0); " +
		"SELECT 'idle', COUNT(pid) FROM pg_stat_activity " +
		"WHERE datname IN ('postgres', 'kine') " +
		"AND state = 'idle in transaction' " +
		"AND state_change < now() - interval '3 minutes'; " +
		"SELECT 'dead', COALESCE((SELECT n_dead_tup FROM pg_stat_user_tables WHERE relname=" + tblQ + "),0), " +
		"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname=" + tblQ + "),0); " +
		"SELECT 'xid', COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database; " +
		"SELECT 'wal', COALESCE((SELECT SUM(size) FROM pg_ls_waldir()),0); " +
		"SELECT 'arch', CASE WHEN failed_count > 0 " +
		"AND last_failed_time > COALESCE(last_archived_time, '-infinity'::timestamptz) " +
		"AND EXTRACT(EPOCH FROM now() - COALESCE(last_archived_time, stats_reset)) > " + strconv.Itoa(archiveStaleSecs) +
		" THEN 1 ELSE 0 END FROM pg_stat_archiver; " +
		"SELECT 'slot', slot_name, " +
		"COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn),0)::bigint " +
		"FROM pg_replication_slots WHERE NOT active; " +
		// mxid_age(datminmxid), NOT age(datminmxid): age() compares against
		// current XID and returns INT32_MAX (2147483647) when datminmxid <
		// FirstNormalTransactionId (3), e.g. fresh clusters with datminmxid=1.
		"SELECT 'mxid', COALESCE(MAX(mxid_age(datminmxid)),0) FROM pg_database; " +
		"SELECT 'invidx', COUNT(indexrelid) FROM pg_index WHERE NOT indisvalid; " +
		"SELECT 'seq', COALESCE(MAX(seq_scan),0), COALESCE(MAX(seq_tup_read),0) " +
		"FROM pg_stat_user_tables WHERE relname=" + tblQ + "; " +
		"SELECT 'idtype', COALESCE((SELECT a.atttypid::bigint FROM pg_attribute a " +
		"JOIN pg_class c ON c.oid = a.attrelid " +
		"JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE n.nspname = current_schema() AND c.relname = " + tblQ +
		" AND a.attname = 'id' AND NOT a.attisdropped), 0); " +
		"SELECT 'seqcliff', COALESCE(MAX(last_value),0), COALESCE(MAX(max_value),0), " +
		"COALESCE(MAX(data_type::text),'') FROM pg_sequences " +
		"WHERE schemaname = current_schema() AND sequencename = " + seqNameExpr + "; " +
		"SELECT 'px', gid FROM pg_prepared_xacts " +
		"WHERE database IN ('postgres','kine') " +
		"AND prepared < now() - interval '" + preparedXactOrphanAge + "'; " +
		"SELECT 'xmin', 'activity', COALESCE(MAX(age(backend_xmin)), 0) FROM pg_stat_activity " +
		"UNION ALL SELECT 'xmin', 'replication', COALESCE(MAX(age(backend_xmin)), 0) " +
		"FROM pg_stat_replication;"
}

func (p *Probe) runProbeBatch(ctx context.Context, pg, user, pass string) *probeBatch {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, kdeps.AppNameProbe, probeBatchSQL(p.d.Cfg.Table))
	if err != nil {
		return &probeBatch{err: err}
	}
	return parseProbeBatch(out)
}

func parseProbeBatch(out string) *probeBatch {
	b := &probeBatch{}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tag, rest, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		switch strings.TrimSpace(tag) {
		case "rev":
			b.revLine, b.revSeen, b.hasTags = rest, true, true
		case "idle":
			b.idleLine, b.idleSeen, b.hasTags = rest, true, true
		case "dead":
			b.deadLine, b.deadSeen, b.hasTags = rest, true, true
		case "xid":
			b.xidLine, b.xidSeen, b.hasTags = rest, true, true
		case "wal":
			b.walLine, b.walSeen, b.hasTags = rest, true, true
		case "arch":
			b.archLine, b.archSeen, b.hasTags = rest, true, true
		case "slot":
			b.slotLines = append(b.slotLines, rest)
			b.hasTags = true
		case "mxid":
			b.mxidLine, b.mxidSeen, b.hasTags = rest, true, true
		case "invidx":
			b.invidxLine, b.invidxSeen, b.hasTags = rest, true, true
		case "seq":
			b.seqLine, b.seqSeen, b.hasTags = rest, true, true
		case "idtype":
			b.idtypeLine, b.idtypeSeen, b.hasTags = rest, true, true
		case "seqcliff":
			b.seqcliffLine, b.seqcliffSeen, b.hasTags = rest, true, true
		case "px":
			b.pxLines = append(b.pxLines, rest)
			b.hasTags = true
		case "xmin":
			b.xminLines = append(b.xminLines, rest)
			b.xminSeen, b.hasTags = true, true
		}
	}
	if b.hasTags {
		b.slotsSeen = true
		b.pxSeen = true
	}
	return b
}

// canFallback reports whether a section missing from batch should fall
// back to its standalone PsqlQuery. When CheckBackendEnv failed, ctx
// is canceled, or the batch itself hit DeadlineExceeded, retrying 6
// standalone queries would only multiply timeout stalls.
func (b *probeBatch) canFallback(ctx context.Context, backendEnv int64) bool {
	if b == nil {
		return true
	}
	if b.err != nil {
		return backendEnv == 1 && ctx.Err() == nil && !errors.Is(b.err, context.DeadlineExceeded)
	}
	return ctx.Err() == nil
}
