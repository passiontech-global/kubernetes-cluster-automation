// config_net.go — the network knobs: NetConfig, its defaults and its
// NODE_HOST_AGENT_* env rows (resolv.conf drift baseline,
// /sys/class/net + overlay MTU reads, the cni-* netns reaper root
// and the node-local-dns datapath probe).
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// NetConfig groups the network knobs: the dns-resolv drift baseline,
// the /sys/class/net + overlay-iface MTU reads (B4), the W9 orphan
// cni-* netns reaper root and the W7-H3 node-local-dns datapath probe.
type NetConfig struct {
	HostResolvConf    string // host resolv.conf (dns drift baseline)
	SysClassNet       string // /sys/class/net — MTU reads (B4)
	NebulaIface       string // overlay iface MTU baseline (neb1 = 1300)
	NetnsDir          string // host /run/netns — orphan cni-* netns files
	LocalDNSProbeAddr string // node-local-dns :53 probe target (169.254.20.10:53)
	LocalDNSProbeName string // query name the DNS probe resolves
}

func (n *NetConfig) applyDefaults() {
	if n.HostResolvConf == "" {
		n.HostResolvConf = defaultHostResolvConf
	}
	if n.SysClassNet == "" {
		n.SysClassNet = defaultSysClassNet
	}
	if n.NebulaIface == "" {
		n.NebulaIface = defaultNebulaIface
	}
	if n.NetnsDir == "" {
		n.NetnsDir = defaultNetnsDir
	}
	if n.LocalDNSProbeAddr == "" {
		n.LocalDNSProbeAddr = defaultLocalDNSProbeAddr
	}
	if n.LocalDNSProbeName == "" {
		n.LocalDNSProbeName = defaultLocalDNSProbeName
	}
}

// envKnobs returns the network domain's env rows — the resolv.conf
// hostPath default and the W7 local-dns probe pair (empty env →
// in-package defaults).
func (n *NetConfig) envKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_HOST_RESOLV_CONF", &n.HostResolvConf,
			hostPath("/etc/resolv.conf")),
		// W7 knobs — empty env → in-package defaults.
		envx.StringKnob("NODE_HOST_AGENT_LOCALDNS_PROBE_ADDR", &n.LocalDNSProbeAddr, ""),
		envx.StringKnob("NODE_HOST_AGENT_LOCALDNS_PROBE_NAME", &n.LocalDNSProbeName, ""),
	}
}
