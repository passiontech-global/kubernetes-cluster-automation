// hygiene_prepared_xacts.go — item 6: orphaned prepared transactions
// (pg_prepared_xacts) — gauge + ROLLBACK PREPARED remediation — and
// the kine-db-xact.prom textfile items 5–6 export through.
package probe

import (
	"context"
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygienePreparedXacts — item 6: prepared transactions orphaned past
// preparedXactOrphanAge on the postgres/kine databases, rolled back
// in place. ROLLBACK PREPARED is the safe release: the coordinator
// is gone by definition (an alive one commits/aborts itself long
// before 15min), and ABORT is the conservative half of the outcome
// — no data commit happens, only the xmin pin releases. A failed
// rollback is noted and retried next round, never fatal.
func (p *Probe) hygienePreparedXacts(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT gid FROM pg_prepared_xacts "+
			"WHERE database IN ('postgres','kine') "+
			"AND prepared < now() - interval '%s'", preparedXactOrphanAge))
	if err != nil {
		note(fmt.Sprintf("prepared-xacts-fail: %v", err))
		return
	}
	h.preparedSeen = true // a successful empty read = no orphans
	for _, gid := range kdeps.ParseGIDs(out) {
		h.preparedXacts++
		if p.d.Cfg.ReadOnly {
			continue // diagnostics only — no ROLLBACK PREPARED
		}
		if _, rerr := p.d.PsqlQuery(ctx, pg, user, pass,
			"ROLLBACK PREPARED "+kdeps.SQLQuote(gid)); rerr != nil {
			note(fmt.Sprintf("rollback-prepared-%s-fail: %v", gid, rerr))
			continue
		}
		h.preparedRolled++
		p.preparedXactRolledBack.Add(1)
		logger().Warn("kinedb: rolled back orphaned prepared transaction",
			"gid", gid)
	}
	if p.d.Cfg.ReadOnly && h.preparedXacts > 0 {
		note(fmt.Sprintf("read-only: %d orphaned prepared xact(s) left in place",
			h.preparedXacts))
	}
}

// emitXactTextfile renders kine-db-xact.prom for items 5–6 — header
// always, sample only behind its *Seen flag (a failed read goes
// absent rather than fabricating a zero), and the lifetime rollback
// counter every round like idleTermTotal.
func (p *Probe) emitXactTextfile(h *hygieneResult) {
	if p.d.Cfg.ReadOnly {
		// A zeroed in-process counter would overwrite the daemon's
		// series — read-only mode never writes textfiles.
		return
	}
	var b promfile.Builder
	mxidHelp := "MAX(age(datminmxid)) across databases — distance " +
		"to MultiXact wraparound pressure."
	if h.mxidSeen {
		b.Gauge("kine_db_multixact_age_transactions", mxidHelp,
			float64(h.mxidAge))
	} else {
		b.Header("kine_db_multixact_age_transactions", mxidHelp)
	}
	preparedHelp := "Prepared transactions older than " +
		preparedXactOrphanAge + " on the postgres/kine databases — " +
		"orphaned xacts pinning the xmin horizon."
	if h.preparedSeen {
		b.Gauge("kine_db_orphan_prepared_xacts", preparedHelp,
			float64(h.preparedXacts))
	} else {
		b.Header("kine_db_orphan_prepared_xacts", preparedHelp)
	}
	b.HeaderType("kine_db_orphan_prepared_xacts_rolled_back_total",
		"Orphaned prepared transactions rolled back by the agent "+
			"(ROLLBACK PREPARED) to release the xmin horizon.", "counter")
	b.Line(fmt.Sprintf("kine_db_orphan_prepared_xacts_rolled_back_total %d",
		p.preparedXactRolledBack.Load()))
	xminHelp := "MAX(age(backend_xmin)) per view — the oldest snapshot " +
		"horizon pinning autovacuum of the kine table (a hung " +
		"query/backup or wedged hot-standby; the reaper is selfheal's)."
	if h.xminSeen {
		b.GaugeLabels("kine_db_backend_xmin_age_transactions", xminHelp,
			`source="activity"`, float64(h.xminActivity))
		b.GaugeLabels("kine_db_backend_xmin_age_transactions", xminHelp,
			`source="replication"`, float64(h.xminReplication))
	} else {
		b.Header("kine_db_backend_xmin_age_transactions", xminHelp)
	}
	// Item 8 — the large-key census: one labelled sample per top-5
	// key, header-only before the first successful census so the
	// family goes absent rather than pinning a stale reading.
	largeKeysHelp := "Live (deleted=0, latest revision) kine keys " +
		"whose value exceeds 512 KiB — the per-key bloat census " +
		"behind the controller-side kine_large_objects audit."
	if h.largeSeen && len(h.largeKeys) > 0 {
		for _, r := range h.largeKeys {
			b.GaugeLabels("kine_db_large_object_bytes", largeKeysHelp,
				fmt.Sprintf("key=\"%s\"",
					promfile.EscapeLabelValue(r.key)),
				float64(r.bytes))
		}
	} else {
		b.Header("kine_db_large_object_bytes", largeKeysHelp)
	}
	p.d.EmitTextfile(xactPromFile, &b)
}
