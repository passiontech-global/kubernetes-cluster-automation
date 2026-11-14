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

func (c *cyc) gate(what, s, msg string, ok func(string) bool) bool {
	if ok(s) {
		return true
	}
	c.err(msg, "what", what, "value", s)
	return false
}

// shToken reports whether a vars-derived value may be interpolated
// into a host shell command.
func (c *cyc) shToken(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe value refused for shell interpolation", converge.SHToken)
}

// shIPCIDR is shToken for IP/prefix values.
func (c *cyc) shIPCIDR(what, s string) bool {
	return c.gate(what, s, "hostconfig: invalid IP/CIDR refused for shell interpolation", converge.SHIPCIDR)
}

// shMarkerBase validates the marker subnet base (interdc_marker_base,
// e.g. "172.29.0") — rules use it as <base>.0/24, so <base>.0 must
// be a valid IPv4 addr (a 3-octet base, NOT a full IP).
func (c *cyc) shMarkerBase(what, s string) bool {
	return c.gate(what, s, "hostconfig: invalid marker base refused for shell interpolation", converge.SHMarkerBase)
}

// shPort is shToken for TCP/UDP ports destined for --dport or
// /dev/tcp interpolation.
func (c *cyc) shPort(what, s string) bool {
	return c.gate(what, s, "hostconfig: invalid port refused for shell interpolation", converge.SHPort)
}

// cfgScalar is the rendered-config sibling of shToken: it gates a
// vars-derived value rendered verbatim as a plain scalar into a
// config file (kubelet KubeletConfiguration YAML, containerd toml).
// A refused value counts a cycle error and skips its own render —
// the remaining lines converge untouched.
func (c *cyc) cfgScalar(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe value refused for config render", converge.CfgScalar)
}

// cfgShellVal is the shell-sourced-conf sibling of cfgScalar: it
// gates a vars-derived/topology scalar rendered into a double-quoted
// KEY="..." line of /etc/node-watchdog.conf (see converge.CfgShellVal
// for why ':' stays legal here while '"', '$' and backtick do not).
// A refused value counts a cycle error and fails the whole render
// closed — the conf is sourced as one unit, so a partially-rendered
// file would silently disable probes.
func (c *cyc) cfgShellVal(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe value refused for watchdog conf render", converge.CfgShellVal)
}

// shExecToken is shToken for values landing in a systemd Exec line
// or its sh -c/bash -c wait-loops — SHToken's charset plus the
// square brackets IPv6 literals need (kine listen/bind addresses,
// TLS paths). Non-empty required, like the *Req variants.
func (c *cyc) shExecToken(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe value refused for exec interpolation", converge.SHExecToken)
}

// cfgEnvVal is cfgScalar for systemd EnvironmentFile KEY=value
// lines — printable ASCII minus the env-file's own quote hazard
// (kine.env's KINE_ENDPOINT DSN keeps its :/?&=).
func (c *cyc) cfgEnvVal(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe value refused for env-file render", converge.CfgEnvVal)
}

// cfgSysctlKey / cfgSysctlVal gate the /etc/sysctl.d pair renders —
// a newline-bearing value would splice further `key = value` lines
// into the drop-in, applied verbatim by `sysctl --system`.
func (c *cyc) cfgSysctlKey(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe sysctl key refused", converge.CfgSysctlKey)
}

func (c *cyc) cfgSysctlVal(what, s string) bool {
	return c.gate(what, s, "hostconfig: unsafe sysctl value refused", converge.CfgSysctlVal)
}

// cfgLimitNOFILE gates the systemd LimitNOFILE= drop-in assignments —
// a value systemd cannot parse is dropped at daemon-reload and the
// unit silently keeps stock fd limits, so a refused value skips the
// drop-in write entirely.
func (c *cyc) cfgLimitNOFILE(what, s string) bool {
	return c.gate(what, s, "hostconfig: invalid LimitNOFILE refused for drop-in render", converge.CfgLimitNOFILE)
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
