// config_cilium.go — the cilium knobs: CiliumConfig, its defaults
// and its NODE_HOST_AGENT_CILIUM_* env rows (the 32/35/38 agent,
// envoy, MTU/WG and BPF-map checks all read this group).
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// CiliumConfig groups the cilium knobs: the 32 agent healthz/socket,
// the 35/38 unix-socket consumers, the B1 envoy probes, the B4/W5.6
// MTU + WireGuard iface knobs and the W8-NM3 BPF map latch ratio.
type CiliumConfig struct {
	HealthzURL      string  // cilium-agent :9879 probe (32)
	Socket          string  // cilium agent unix socket (35)
	EnvoyReadyURL   string  // cilium-envoy admin :9964/ready
	EnvoyAdminURL   string  // envoy :9901 /stats?filter=update_rejected
	Iface           string  // cilium host iface (cilium_net)
	WG0Iface        string  // cilium WG tunnel iface (cilium_wg0)
	RuntimeConfig   string  // agent-runtime-config.json MTU fallback
	BPFMapHighRatio float64 // critical-map fill ratio → latch (0.90)
}

func (cl *CiliumConfig) applyDefaults() {
	if cl.HealthzURL == "" {
		cl.HealthzURL = DefaultCiliumHealthzURL
	}
	if cl.Socket == "" {
		cl.Socket = defaultCiliumSocket
	}
	if cl.EnvoyReadyURL == "" {
		cl.EnvoyReadyURL = defaultCiliumEnvoyReadyURL
	}
	if cl.EnvoyAdminURL == "" {
		cl.EnvoyAdminURL = defaultCiliumEnvoyAdminURL
	}
	if cl.Iface == "" {
		cl.Iface = defaultCiliumIface
	}
	if cl.WG0Iface == "" {
		cl.WG0Iface = defaultCiliumWG0Iface
	}
	if cl.RuntimeConfig == "" {
		cl.RuntimeConfig = defaultCiliumRuntimeConfig
	}
	if cl.BPFMapHighRatio <= 0 {
		cl.BPFMapHighRatio = defaultBPFMapHighRatio
	}
}

// envKnobs returns the cilium domain's env rows — the agent unix
// socket (hostPath default) and the envoy admin stats URL (empty env
// → in-package default).
func (cl *CiliumConfig) envKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_CILIUM_SOCKET", &cl.Socket,
			hostPath("/run/cilium/cilium.sock")),
		// W7 knob — empty env → in-package default.
		envx.StringKnob("NODE_HOST_AGENT_CILIUM_ENVOY_ADMIN_URL", &cl.EnvoyAdminURL, ""),
	}
}
