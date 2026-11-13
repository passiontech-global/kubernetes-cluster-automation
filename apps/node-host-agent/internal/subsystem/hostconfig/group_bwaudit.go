// group_bwaudit.go — T11 per-peer nebula bandwidth accounting
// (counter-only inet nft table; cannot break traffic).
package hostconfig

import (
	"fmt"
	"strings"
)

// ---------- T11 bw audit ----------

func (c *cyc) groupBwAudit() {
	if !c.vb("interdc_nebula_enabled") || !c.t.Found {
		return
	}
	dev := defStr(c.v("interdc_nebula_dev"), "neb1")
	var in, out strings.Builder
	for _, a := range c.t.BwAuditTargets {
		// The values land verbatim inside an nft ruleset — an
		// iifname/comment with a control byte or quote would splice
		// arbitrary rules in. Refused values count via the gate and
		// skip the whole ruleset (fail closed, partial renders never
		// deploy).
		if !c.cfgScalar("interdc_nebula_dev", dev) ||
			!c.shIPCIDR("bwaudit addr "+a.Label, a.Addr) ||
			!c.cfgScalar("bwaudit label "+a.Label, a.Label) {
			return
		}
		fmt.Fprintf(&in, "        iifname \"%s\" ip saddr %s counter comment \"%s in-neb\"\n", dev, a.Addr, a.Label)
		fmt.Fprintf(&out, "        oifname \"%s\" ip daddr %s counter comment \"%s out-neb\"\n", dev, a.Addr, a.Label)
	}
	nft := fmt.Sprintf(`# Managed by node-config-agent - per-peer bandwidth accounting on
# %s.
# Counter-only + policy accept: cannot break traffic.
# Inspect: nft list table inet interdc_acct
destroy table inet interdc_acct
table inet interdc_acct {
    chain input {
        type filter hook input priority filter; policy accept;
%s    }
    chain output {
        type filter hook output priority filter; policy accept;
%s    }
}
`, dev, in.String(), out.String())
	c.applyNftUnit("interdc-acct", "/etc/interdc-acct.nft",
		[]byte(nft), "interdc per-peer bandwidth accounting (nft counters)")
	// sweep the invented first-port deployment (wrong table + paths)
	_, _ = c.r.run(c.ctx, "systemctl", "disable", "--now", "interdc-bw-audit.service")
	_, _ = c.r.removeManaged("/etc/systemd/system/interdc-bw-audit.service")
	_, _ = c.r.removeManaged("/etc/nftables.d/interdc-bw-audit.nft")
}
