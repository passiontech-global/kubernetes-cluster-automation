// config_calico.go — the calico-hygiene calico-hygiene knobs: CalicoConfig,
// its defaults and its NODE_HOST_AGENT_CALICO_* env rows (the felix
// readiness probe and the orphan cali* veth leak headroom).
package wdeps

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// CalicoConfig groups the calico-hygiene calico-hygiene knobs — the felix
// readiness probe and the orphan cali* veth leak headroom.
type CalicoConfig struct {
	FelixReadyURL       string // calico-node felix :9099/readiness probe
	OrphanVethThreshold int    // cali* ifaces above the pod count → leak (50)
}

func (cl *CalicoConfig) applyDefaults() {
	if cl.FelixReadyURL == "" {
		cl.FelixReadyURL = DefaultCalicoFelixReadyURL
	}
	if cl.OrphanVethThreshold <= 0 {
		cl.OrphanVethThreshold = defaultCalicoOrphanVethThresh
	}
}

// envKnobs returns the calico domain's env rows — the felix
// readiness URL (empty env → in-package default) and the
// orphan-veth threshold.
func (cl *CalicoConfig) envKnobs() []envx.Knob {
	return []envx.Knob{
		envx.StringKnob(envnames.EnvCalicoFelixReadyURL, &cl.FelixReadyURL, ""),
		envx.IntKnob(envnames.EnvCalicoOrphanVethThreshold, &cl.OrphanVethThreshold, defaultCalicoOrphanVethThresh),
	}
}
