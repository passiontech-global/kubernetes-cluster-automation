// shell_gates.go — the cyc sh -c interpolation gates, split out of
// hostconfig.go (which keeps the Reconciler lifecycle, the managed
// file helpers and the systemd verb wrappers). Several groups build
// `sh -c`/`bash -c` command strings with vars-derived values (nebula
// tables/dev, mesh IPs, ports); the charset/shape predicates live in
// the converge package — these wrappers add the cycle-error
// attribution: a refused value counts a cycle error AND refuses the
// shell work.
package hostconfig

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig/converge"
)

// shToken reports whether a vars-derived value may be interpolated
// into a host shell command.
func (c *cyc) shToken(what, s string) bool {
	if converge.SHToken(s) {
		return true
	}
	c.err("hostconfig: unsafe value refused for shell interpolation",
		"what", what, "value", s)
	return false
}

// shIPCIDR is shToken for IP/prefix values.
func (c *cyc) shIPCIDR(what, s string) bool {
	if converge.SHIPCIDR(s) {
		return true
	}
	c.err("hostconfig: invalid IP/CIDR refused for shell interpolation",
		"what", what, "value", s)
	return false
}

// shMarkerBase validates the marker subnet base (interdc_marker_base,
// e.g. "172.29.0") — rules use it as <base>.0/24, so <base>.0 must
// be a valid IPv4 addr (a 3-octet base, NOT a full IP).
func (c *cyc) shMarkerBase(what, s string) bool {
	if converge.SHMarkerBase(s) {
		return true
	}
	c.err("hostconfig: invalid marker base refused for shell interpolation",
		"what", what, "value", s)
	return false
}

// shPort is shToken for TCP/UDP ports destined for --dport or
// /dev/tcp interpolation.
func (c *cyc) shPort(what, s string) bool {
	if converge.SHPort(s) {
		return true
	}
	c.err("hostconfig: invalid port refused for shell interpolation",
		"what", what, "value", s)
	return false
}

// cfgScalar is the rendered-config sibling of shToken: it gates a
// vars-derived value rendered verbatim as a plain scalar into a
// config file (kubelet KubeletConfiguration YAML, containerd toml).
// A refused value counts a cycle error and skips its own render —
// the remaining lines converge untouched.
func (c *cyc) cfgScalar(what, s string) bool {
	if converge.CfgScalar(s) {
		return true
	}
	c.err("hostconfig: unsafe value refused for config render",
		"what", what, "value", s)
	return false
}

// cfgShellVal is the shell-sourced-conf sibling of cfgScalar: it
// gates a vars-derived/topology scalar rendered into a double-quoted
// KEY="..." line of /etc/node-watchdog.conf (see converge.CfgShellVal
// for why ':' stays legal here while '"', '$' and backtick do not).
// A refused value counts a cycle error and fails the whole render
// closed — the conf is sourced as one unit, so a partially-rendered
// file would silently disable probes.
func (c *cyc) cfgShellVal(what, s string) bool {
	if converge.CfgShellVal(s) {
		return true
	}
	c.err("hostconfig: unsafe value refused for watchdog conf render",
		"what", what, "value", s)
	return false
}

// cfgSysctlKey / cfgSysctlVal gate the /etc/sysctl.d pair renders —
// a newline-bearing value would splice further `key = value` lines
// into the drop-in, applied verbatim by `sysctl --system`.
func (c *cyc) cfgSysctlKey(what, s string) bool {
	if converge.CfgSysctlKey(s) {
		return true
	}
	c.err("hostconfig: unsafe sysctl key refused", "what", what, "value", s)
	return false
}

func (c *cyc) cfgSysctlVal(what, s string) bool {
	if converge.CfgSysctlVal(s) {
		return true
	}
	c.err("hostconfig: unsafe sysctl value refused", "what", what, "value", s)
	return false
}

// cfgLimitNOFILE gates the systemd LimitNOFILE= drop-in assignments —
// a value systemd cannot parse is dropped at daemon-reload and the
// unit silently keeps stock fd limits, so a refused value skips the
// drop-in write entirely.
func (c *cyc) cfgLimitNOFILE(what, s string) bool {
	if converge.CfgLimitNOFILE(s) {
		return true
	}
	c.err("hostconfig: invalid LimitNOFILE refused for drop-in render",
		"what", what, "value", s)
	return false
}

// The *Req variants are the same gates for slots where the value is
// REQUIRED: an empty value there cannot inject, but it still emits a
// malformed command (`ip route replace default dev neb1 src <blank>`,
// `--dport <blank>`) that only fails at Debug level inside sh -c.
// Required slots count an empty value as a cycle error instead.
func (c *cyc) shIPCIDRReq(what, s string) bool {
	if s == "" {
		c.err("hostconfig: required IP/CIDR empty — refusing shell interpolation",
			"what", what)
		return false
	}
	return c.shIPCIDR(what, s)
}

func (c *cyc) shPortReq(what, s string) bool {
	if s == "" {
		c.err("hostconfig: required port empty — refusing shell interpolation",
			"what", what)
		return false
	}
	return c.shPort(what, s)
}
