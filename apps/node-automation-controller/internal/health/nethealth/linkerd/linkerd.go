// linkerd.go — the facade of the linkerd check package: the three
// sweep constructors (webhookguard-facade precedent). The duty files
// beside it own the check logic; the registry and the cluster-health
// sweep wire only these three entry points.
package linkerd

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// NewLinkerdEndpointSyncCheck builds the netns-endpoint-sync endpoint-sync check —
// every ledger is zero-value ready, so the constructor carries no
// initialization.
func NewLinkerdEndpointSyncCheck(d *probefw.Deps) probefw.Check {
	return &linkerdEndpointSyncCheck{Deps: d}
}

// NewLinkerdH2StreamGuardCheck builds the h2 guard — resolves
// LINKERD_H2_STREAM_GUARD_EVICT_ENABLED once at construction and
// leaves the emitted-gauge ledgers zero-value ready; pod-delete
// cooldowns ride the shared Deps.Heals set.
func NewLinkerdH2StreamGuardCheck(d *probefw.Deps) probefw.Check {
	return &linkerdH2StreamGuardCheck{
		Deps:         d,
		evictEnabled: envx.Gate("LINKERD_H2_STREAM_GUARD_EVICT_ENABLED", true),
	}
}

// NewLinkerdProtocolDetectionStallCheck builds the opaque-ports stall
// check — zero-value ledgers, no initialization.
func NewLinkerdProtocolDetectionStallCheck(d *probefw.Deps) probefw.Check {
	return &linkerdProtocolDetectionStallCheck{Deps: d}
}
