// config.go — env resolution for the nethealth checks' own knobs:
// LinkerdConfigFromEnv fills c.Linkerd once at sweep Setup, called
// from clusterhealthprobes.healthProbeConfigFromEnv (the same
// delegation ported.ConfigFromEnv / watchdogs.KCMConfigFromEnv /
// datastore.ConfigFromEnv use), so the gate resolves before the
// module's Disabled check and never inside a sweep.
package nethealth

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// LinkerdOutlierEvictEnabledDefault keeps the W13-NM2 auto-evict
	// armed unless an operator explicitly sets
	// LINKERD_OUTLIER_EVICT_ENABLED=false — the Resolved Design
	// Decisions default (auto-evict on with the six safety gates).
	LinkerdOutlierEvictEnabledDefault = true
)

// LinkerdConfigFromEnv fills c.Linkerd from the LINKERD_* env vars.
// The evict toggle goes through envx.Gate (the strict sub-feature
// gate helper — enabled unless the value is exactly "false"):
// detection and the outlier gauge run either way, only the pod
// eviction is gated.
func LinkerdConfigFromEnv(c *probefw.Config) {
	c.Linkerd = probefw.LinkerdConfig{
		OutlierEvictEnabled: envx.Gate(
			"LINKERD_OUTLIER_EVICT_ENABLED", LinkerdOutlierEvictEnabledDefault),
	}
}
