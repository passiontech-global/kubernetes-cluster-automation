// hygiene_catalog.go — items 5 + 7a: the combined read-only catalog
// censuses (MultiXact horizon, invalid indexes, seq-scan counters)
// and the pg_index/pg_stat_* single-exec batching behind them.
package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneCatalog — items 5 + 7: the three read-only catalog
// censuses run as ONE multi-statement psql exec. A podman/docker
// exec spawn is the dominant per-query cost of the 2-minute loop,
// and these three carry no remediation and no cross-statement
// dependency, so one round-trip serves all three (the ROLLBACK
// PREPARED / ANALYZE / VACUUM mutations stay in their own
// condition-gated execs). Statement order fixes the output line
// order — one row per statement under -tAc. A failing statement
// aborts the whole implicit transaction and exits non-zero, which
// notes all three -fail tags exactly as the three separate execs
// did; a short or unparseable line gates only its own series under
// the original -unparsed tag (a series never fabricates a zero).
//
// hygieneMultiXact (item 5): MultiXact IDs are consumed by
// row-level SHARE locks (foreign keys checking referenced rows);
// exhaustion forces the same emergency freeze cycle as XID
// wraparound, so the mxid gauge rides the same 2-minute freshness
// as kine_db_xid_age_transactions.
//
// hygieneInvalidIndexes (item 7a, invalid-index-reaper): indexes
// with indisvalid=false across pg_index. An invalid index is dead
// weight — every INSERT still maintains it but the planner never
// uses it, and the next REINDEX CONCURRENTLY errors or silently
// leaves it. The probe only counts (kine_db_invalid_indexes feeds
// the alert); the DROP itself belongs to the maint cycle's
// invalid-index reaper (maint package) where the daily
// serialisation already gates the index churn.
// COUNT(indexrelid), not COUNT(*): the probe contract bans a bare
// COUNT(*) in the 2-minute loop — counting a catalog column is
// semantically identical and keeps the kine-heap seq-scan guard
// (probe_test.go) airtight.
func (p *Probe) hygieneCatalog(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	tblQ := kdeps.SQLQuote(p.d.Cfg.Table)
	// Resolve the sequence by OID rather than string-parsing
	// pg_get_serial_sequence — quoted/dotted names survive the regclass
	// cast. pg_class.relname is the raw pg_sequences.sequencename.
	seqByOID := "(SELECT c.relname FROM pg_class c WHERE c.oid = " +
		"pg_get_serial_sequence(" + tblQ + ", 'id')::regclass)"
	// kine.id may have no OWNED BY link, so pg_get_serial_sequence() returns
	// NULL. The pg_sequences WHERE must fall back to <table>_id_seq just like
	// the reported sequence name; otherwise the clause matches zero rows,
	// MAX(max_value) is 0 and parseSeqCliffLines drops the whole reading.
	seqFallbackQ := kdeps.SQLQuote(p.d.Cfg.Table + "_id_seq")
	seqNameExpr := "COALESCE(" + seqByOID + ", " + seqFallbackQ + ")"
	sql := "SELECT COALESCE(MAX(age(datminmxid)),0) FROM pg_database; " +
		"SELECT COUNT(indexrelid) FROM pg_index WHERE NOT indisvalid; " +
		// MAX() folds the empty stats view into one 0|0 row. A plain
		// SELECT returned ZERO rows under psql -tAc, shifting line(3)
		// (atttypid) and line(4) (seq cliff) up by one and misparsing both.
		"SELECT COALESCE(MAX(seq_scan),0), COALESCE(MAX(seq_tup_read),0) " +
		"FROM pg_stat_user_tables WHERE relname=" + tblQ + "; " +
		"SELECT COALESCE((SELECT a.atttypid::bigint FROM pg_attribute a " +
		"JOIN pg_class c ON c.oid = a.attrelid " +
		"JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE n.nspname = current_schema() AND c.relname = " + tblQ +
		" AND a.attname = 'id' AND NOT a.attisdropped), 0); " +
		// One pg_sequences read for all three columns (was three
		// correlated subqueries). MAX keeps the single-row shape.
		"SELECT COALESCE(MAX(last_value),0), COALESCE(MAX(max_value),0), " +
		"COALESCE(MAX(data_type::text),'') FROM pg_sequences " +
		"WHERE schemaname = current_schema() AND sequencename = " + seqNameExpr + ";"
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, kdeps.AppNameProbe, sql)
	if err != nil {
		note(fmt.Sprintf("mxid-age-fail: %v", err))
		note(fmt.Sprintf("invalid-indexes-fail: %v", err))
		note(fmt.Sprintf("seq-scan-fail: %v", err))
		note(fmt.Sprintf("seq-cliff-fail: %v", err))
		return
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	line := func(i int) string {
		if i < len(lines) {
			return lines[i]
		}
		return ""
	}
	if v, perr := strconv.ParseInt(line(0), 10, 64); perr != nil {
		note(fmt.Sprintf("mxid-age-unparsed: %v", perr))
	} else {
		h.mxidAge, h.mxidSeen = v, true
	}
	if v, perr := strconv.ParseInt(line(1), 10, 64); perr != nil {
		note(fmt.Sprintf("invalid-indexes-unparsed: %v", perr))
	} else {
		h.invalidIdx, h.invalidSeen = v, true
	}
	scans, tupRead, perr := kdeps.ParsePair(line(2))
	if perr != nil {
		// An empty result means the stats view has no row for the
		// table yet — inconclusive, like a parse failure.
		note(fmt.Sprintf("seq-scan-unparsed: %v", perr))
	} else {
		h.seqScans, h.seqTupRead, h.seqSeen = scans, tupRead, true
	}
	p.parseSeqCliffLines(line(3), line(4), h, note)
}

const (
	pgTypeInt8 int64 = 20
	pgTypeInt4 int64 = 23
	int4MaxVal int64 = 2147483647
)

func (p *Probe) parseSeqCliffLines(typeLine, seqLine string, h *hygieneResult, note func(string)) {
	typeLine = strings.TrimSpace(typeLine)
	seqLine = strings.TrimSpace(seqLine)
	if typeLine == "" || seqLine == "" {
		return
	}
	attType, err := strconv.ParseInt(typeLine, 10, 64)
	if err != nil {
		note(fmt.Sprintf("seq-cliff-type-unparsed: %v", err))
		return
	}
	parts := strings.Split(seqLine, "|")
	if len(parts) != 3 {
		note(fmt.Sprintf("seq-cliff-seq-unparsed: want 3 fields, got %d", len(parts)))
		return
	}
	lastVal, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		note(fmt.Sprintf("seq-cliff-last-unparsed: %v", err))
		return
	}
	maxVal, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		note(fmt.Sprintf("seq-cliff-max-unparsed: %v", err))
		return
	}
	dataType := strings.TrimSpace(parts[2])
	if attType == 0 || maxVal <= 0 {
		// Table or sequence absent — keep unseen rather than emitting 0.
		return
	}
	effectiveCeiling := maxVal
	if attType == pgTypeInt4 && effectiveCeiling > int4MaxVal {
		effectiveCeiling = int4MaxVal
	}
	ratio := float64(lastVal) / float64(effectiveCeiling)
	if ratio < 0 {
		ratio = 0
	}
	hazard := 0.0
	if attType == pgTypeInt4 || dataType != "bigint" || maxVal <= int4MaxVal {
		hazard = 1.0
	}
	h.seqUtilRatio = ratio
	h.idInt4Hazard = hazard
	h.seqCliffSeen = true
	p.d.M.SeqUtilRatio.Set(ratio)
	p.d.M.IDInt4Hazard.Set(hazard)
	if hazard == 1 && ratio >= 0.50 {
		note(fmt.Sprintf("kine-id-int4-cliff-warning: atttypid=%d seq_type=%s util=%.3f",
			attType, dataType, ratio))
	}
}
