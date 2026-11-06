// checks.go — the cilium check family constructors. The parent
// workerhygiene package wires these into its ordered dispatch list;
// each check holds the shared *wdeps.Deps and owns its own streak
// state. Check order is load-bearing — see the parent's initChecks.
package cilium

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// NewCilium returns the 32-cilium healthz check (sig9 + the W8-NM3
// BPF-map probe that rides inside it).
func NewCilium(d *wdeps.Deps) *CiliumCheck { return &CiliumCheck{d: d} }

// NewCiliumInit returns the 35 endpoints-stuck-in-init check (sig15).
func NewCiliumInit(d *wdeps.Deps) *CiliumInitCheck {
	return &CiliumInitCheck{d: d}
}

// NewCiliumIPAM returns the 38 IPAM leak detector.
func NewCiliumIPAM(d *wdeps.Deps) *CiliumIPAMCheck {
	return &CiliumIPAMCheck{d: d}
}

// NewCiliumEnvoy returns the B1 envoy readiness/xDS-NACK guard.
func NewCiliumEnvoy(d *wdeps.Deps) *CiliumEnvoyCheck {
	return &CiliumEnvoyCheck{d: d}
}

// NewCiliumMTU returns the B4 MTU-drift guard.
func NewCiliumMTU(d *wdeps.Deps) *CiliumMTUCheck {
	return &CiliumMTUCheck{d: d}
}

// NewCiliumWG returns the W5.6 WireGuard peer-deficit check.
func NewCiliumWG(d *wdeps.Deps) *CiliumWGCheck { return &CiliumWGCheck{d: d} }

// NewCiliumLRP returns the W7-H3 node-local-dns LRP datapath probe.
func NewCiliumLRP(d *wdeps.Deps) *CiliumLRPCheck {
	return &CiliumLRPCheck{d: d}
}
