// config_net.go — the network knobs: NetConfig, its defaults and its
// NODE_HOST_AGENT_* env rows (the cni-* netns reaper root and the
// node-local-dns datapath probe). The shared net wiring (resolv.conf
// drift baseline, /sys/class/net, overlay MTU iface) promoted to the
// top-level Config — see config.go.
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// NetConfig groups the network knobs: the orphan cni-* netns
// reaper root and the envoy-xds-lrp node-local-dns datapath probe.
type NetConfig struct {
	NetnsDir          string // host /run/netns — orphan cni-* netns files
	LocalDNSProbeAddr string // node-local-dns :53 probe target (169.254.20.10:53)
	LocalDNSProbeName string // query name the DNS probe resolves
}

func (n *NetConfig) applyDefaults() {
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

// envKnobs returns the network domain's env rows — the local-dns
// probe pair (empty env → in-package defaults).
func (n *NetConfig) envKnobs() []envx.Knob {
	return []envx.Knob{
		// env knobs — empty env → in-package defaults.
		envx.StringKnob(envnames.EnvLocaldnsProbeAddr, &n.LocalDNSProbeAddr, ""),
		envx.StringKnob(envnames.EnvLocaldnsProbeName, &n.LocalDNSProbeName, ""),
	}
}
