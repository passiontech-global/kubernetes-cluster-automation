// hygiene_xid.go — item 3: the XID wraparound gauge
// (MAX(age(datfrozenxid))); the freeze remediation stays in the
// maint cycle.
package probe

import (
	"context"
)

// hygieneXID — item 3: MAX(age(datfrozenxid)) across databases. Only
// the gauge lives here; the VACUUM (FREEZE, ANALYZE) remediation is
// xidFreezeCheck in the maint cycle.
func (p *Probe) hygieneXID(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	v, err := p.d.QueryXidAge(ctx, pg, user, pass)
	if err != nil {
		note(err.Error())
		return
	}
	h.xidAge, h.xidSeen = v, true
}
