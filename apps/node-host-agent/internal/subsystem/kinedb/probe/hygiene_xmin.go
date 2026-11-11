// hygiene_xmin.go — item 9: the long-running backend_xmin horizon
// (roadmap B7): kine is append-only + DELETE-heavy, so ONE hung
// query/backup session pinning an old backend_xmin blocks autovacuum
// from reclaiming dead tuples on the kine table even while COMPACT
// keeps succeeding — the index bloat the maint cycle fights is the
// downstream symptom. MAX(age(backend_xmin)) is read per view (2-minute
// freshness like the XID wraparound gauge; the remediation half —
// terminate the idle holder — is selfheal.go's session reaper) and
// exported through the kine-db-xact.prom textfile (items 5–8 parity:
// the collector list lives in kdeps/probe.go, the textfile channel
// is the export path).
//
//   - pg_stat_activity.backend_xmin — the xmin each backend is
//     holding (idle-in-tx, cursors, the replication walsender's
//     standby feedback when the standby is silent).
//   - pg_stat_replication.backend_xmin — the xmin a PHYSICAL
//     standby reports; a wedged hot-standby pins the horizon
//     invisibly to pg_stat_activity.
package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// hygieneBackendXmin reads MAX(age(backend_xmin)) from both views —
// one UNION ALL round-trip, `source|age` rows (psql -tA). A failed
// query leaves xminSeen false: the series goes absent rather than
// fabricating a zero over a real horizon (the seen-gating contract).
func (p *Probe) hygieneBackendXmin(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT 'activity', COALESCE(MAX(age(backend_xmin)), 0) FROM pg_stat_activity "+
			"UNION ALL SELECT 'replication', COALESCE(MAX(age(backend_xmin)), 0) "+
			"FROM pg_stat_replication")
	if err != nil {
		note(fmt.Sprintf("backend-xmin-fail: %v", err))
		return
	}
	h.xminSeen = true // a successful read answers for BOTH views
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 2 {
			continue
		}
		age, perr := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
		if perr != nil {
			continue // malformed row — never emit junk
		}
		switch strings.TrimSpace(f[0]) {
		case "activity":
			h.xminActivity = age
		case "replication":
			h.xminReplication = age
		}
	}
}
