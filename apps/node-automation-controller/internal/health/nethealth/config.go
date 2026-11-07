// config.go — env resolution for the nethealth checks' own knobs:
// LinkerdConfigFromEnv returns the LinkerdConfig and
// CiliumConfigFromEnv the CiliumConfig — the cilium checks live in
// this package, so their CILIUM_* resolver moved here from probefw
// alongside its only consumers. Both resolve once at sweep Setup from
// clusterhealthprobes.healthProbeConfigFromEnv (the same delegation
// datastore.ConfigFromEnv / watchdogs.KCMConfigFromEnv use), so the
// knobs resolve before the module's Disabled check and never inside
// a sweep.
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

// LinkerdConfigFromEnv resolves cfg.Linkerd's knobs — the LINKERD_*
// env vars — as the sub-struct the caller assigns. The evict toggle
// goes through envx.Gate (the strict sub-feature gate helper —
// enabled unless the value is exactly "false"): detection and the
// outlier gauge run either way, only the pod eviction is gated.
func LinkerdConfigFromEnv() probefw.LinkerdConfig {
	return probefw.LinkerdConfig{
		OutlierEvictEnabled: envx.Gate(
			"LINKERD_OUTLIER_EVICT_ENABLED", LinkerdOutlierEvictEnabledDefault),
	}
}

// CiliumConfigFromEnv resolves cfg.Cilium's knobs — the CILIUM_* env
// vars backing the cilium nethealth checks — as the sub-struct the
// caller assigns. Both knobs go through GetenvFloatPositive: >1 keeps
// working as the documented "disable this check" escape and <=0 falls
// back to the default — the same contract the retired healthEnvFloat
// had.
func CiliumConfigFromEnv() probefw.CiliumConfig {
	return probefw.CiliumConfig{
		BPFMapPressureThreshold: envx.GetenvFloatPositive(
			"CILIUM_BPF_MAP_PRESSURE_THRESHOLD", probefw.CiliumBPFMapPressureDefault),
		NodeIPAMMinFreeRatio: envx.GetenvFloatPositive(
			"CILIUM_NODE_IPAM_MIN_FREE_RATIO", probefw.CiliumNodeIPAMMinFreeDefault),
	}
}
