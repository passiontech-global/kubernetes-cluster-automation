// hygiene_xid.go — item 3: the XID wraparound gauge
// (MAX(age(datfrozenxid))); the freeze remediation stays in the
// maint cycle.
package probe

import (
	"context"
	"fmt"
	"strconv"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneXID — item 3: MAX(age(datfrozenxid)) across databases. Only
// the gauge lives here; the VACUUM (FREEZE, ANALYZE) remediation is
// xidFreezeCheck in the maint cycle.
func (p *Probe) hygieneXID(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database")
	if err != nil {
		note(fmt.Sprintf("xid-age-fail: %v", err))
		return
	}
	v, perr := strconv.ParseInt(kdeps.FirstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("xid-age-unparsed: %v", perr))
		return
	}
	h.xidAge, h.xidSeen = v, true
}
