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
	out, err := p.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datminmxid)),0) FROM pg_database; "+
			"SELECT COUNT(indexrelid) FROM pg_index WHERE NOT indisvalid; "+
			"SELECT COALESCE(seq_scan,0), COALESCE(seq_tup_read,0) "+
			"FROM pg_stat_user_tables WHERE relname="+
			kdeps.SQLQuote(p.d.Cfg.Table))
	if err != nil {
		note(fmt.Sprintf("mxid-age-fail: %v", err))
		note(fmt.Sprintf("invalid-indexes-fail: %v", err))
		note(fmt.Sprintf("seq-scan-fail: %v", err))
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
		return
	}
	h.seqScans, h.seqTupRead, h.seqSeen = scans, tupRead, true
}
