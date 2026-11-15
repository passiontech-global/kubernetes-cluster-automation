// hygiene_stats.go — the merged read-only scalar census: ONE
// multi-statement psql exec answers the five unconditional
// single-row stats reads the hygiene block used to fork separately
// (idle-in-tx count, dead/live tuples, XID age, pg_wal bytes,
// archiver staleness). A podman exec + psql spawn dominated the
// per-query cost of the 2-minute loop; these five carry no
// remediation and no cross-statement dependency, so one round-trip
// serves all five — the hygiene_catalog.go precedent.
//
// Contract notes:
//   - Every statement is an aggregate or scalar-subquery shape so
//     it ALWAYS emits exactly one row — a missing pg_stat_user_tables
//     row for the kine table reads 0|0, never a shifted line.
//   - Statement order fixes output line order under -tAc; a
//     failing statement aborts the implicit transaction and exits
//     non-zero, which notes all five -fail tags exactly as the
//     five separate execs did. A short/unparseable line gates only
//     its own series under the original -unparsed tag.
package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneScalarStats runs the five read-only census statements as
// ONE psql exec and fills the corresponding hygieneResult fields.
// Called first in pgHygiene — hygieneDeadTuple's vacuum gate and
// hygieneWAL's disk-ratio read consume the fields it sets.
func (p *Probe) hygieneScalarStats(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	table := kdeps.SQLQuote(p.d.Cfg.Table)
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, kdeps.AppNameProbe,
		// 1. idle-in-transaction census (COUNT(pid), never COUNT(*)
		// — the probe contract bans a bare COUNT(*) on the kine heap).
		"SELECT COUNT(pid) FROM pg_stat_activity "+
			"WHERE datname IN ('postgres', 'kine') "+
			"AND state = 'idle in transaction' "+
			"AND state_change < now() - interval '3 minutes'; "+
			// 2. dead/live tuples — scalar subqueries so a missing
			// stats row still yields one "0|0" line (positional
			// parsing cannot survive a zero-row statement).
			"SELECT COALESCE((SELECT n_dead_tup FROM pg_stat_user_tables "+
			"WHERE relname="+table+"),0), "+
			"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables "+
			"WHERE relname="+table+"),0); "+
			// 3. XID wraparound horizon.
			"SELECT COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database; "+
			// 4. total WAL bytes (pg_ls_waldir).
			"SELECT COALESCE((SELECT SUM(size) FROM pg_ls_waldir()),0); "+
			// 5. archiver continuously-failing staleness.
			"SELECT CASE WHEN failed_count > 0 "+
			"AND last_failed_time > COALESCE(last_archived_time, '-infinity'::timestamptz) "+
			"AND EXTRACT(EPOCH FROM now() - COALESCE(last_archived_time, stats_reset)) > "+
			strconv.Itoa(archiveStaleSecs)+
			" THEN 1 ELSE 0 END FROM pg_stat_archiver")
	if err != nil {
		note(fmt.Sprintf("idle-tx-fail: %v", err))
		note(fmt.Sprintf("dead-tuple-fail: %v", err))
		note(fmt.Sprintf("xid-age-fail: %v", err))
		note(fmt.Sprintf("wal-size-fail: %v", err))
		note(fmt.Sprintf("archiver-fail: %v", err))
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
		note(fmt.Sprintf("idle-tx-unparsed: %v", perr))
	} else {
		h.idleInTx, h.idleSeen = v, true
	}
	if dead, live, perr := kdeps.ParsePair(line(1)); perr != nil {
		note(fmt.Sprintf("dead-tuple-unparsed: %v", perr))
	} else {
		h.deadTup, h.deadSeen = dead, true
		h.deadRatio = float64(dead) / float64(max(live, 1))
	}
	if v, perr := strconv.ParseInt(line(2), 10, 64); perr != nil {
		note(fmt.Sprintf("xid-age-unparsed: %v", perr))
	} else {
		h.xidAge, h.xidSeen = v, true
	}
	if v, perr := strconv.ParseInt(line(3), 10, 64); perr != nil {
		note(fmt.Sprintf("wal-size-unparsed: %v", perr))
	} else {
		h.walBytes, h.walSeen = v, true
	}
	if v, perr := strconv.ParseInt(line(4), 10, 64); perr != nil {
		note(fmt.Sprintf("archiver-unparsed: %v", perr))
	} else {
		h.archiveStale, h.archiveSeen = v, true
	}
}
