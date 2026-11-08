// linkerd.go — the facade of the linkerd check package: the three
// sweep constructors (webhookguard-facade precedent). The duty files
// beside it own the check logic; the registry and the cluster-health
// sweep wire only these three entry points.
package linkerd

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
)

// NewLinkerdEndpointSyncCheck builds the W9-NM2 endpoint-sync check —
// every ledger is zero-value ready, so the constructor carries no
// initialization.
func NewLinkerdEndpointSyncCheck(d *probefw.Deps) probefw.Check {
	return &linkerdEndpointSyncCheck{Deps: d}
}

// NewLinkerdH2StreamGuardCheck builds the h2 guard — its only state
// is the emitted-gauge ledgers; pod-delete cooldowns ride the shared
// Deps.Heals set.
func NewLinkerdH2StreamGuardCheck(d *probefw.Deps) probefw.Check {
	return &linkerdH2StreamGuardCheck{Deps: d}
}

// NewLinkerdProtocolDetectionStallCheck builds the opaque-ports stall
// check — zero-value ledgers, no initialization.
func NewLinkerdProtocolDetectionStallCheck(d *probefw.Deps) probefw.Check {
	return &linkerdProtocolDetectionStallCheck{Deps: d}
}
