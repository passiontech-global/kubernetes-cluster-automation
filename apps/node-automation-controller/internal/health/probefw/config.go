// config.go — env resolution for framework-owned check knobs:
// CiliumConfigFromEnv fills c.Cilium — the cilium nethealth checks'
// env knobs — once at sweep Setup. The checks used to re-read env
// inside Run; resolve-at-Setup matches every other knob family
// (ported.ConfigFromEnv / watchdogs.KCMConfigFromEnv are the
// per-domain peers this joins in
// clusterhealthprobes.healthProbeConfigFromEnv).
package probefw

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Defaults matching the live checks — they used to live as
// unexported consts beside each check's Run; the migrating checks
// read the resolved Config field instead.
const (
	// CiliumBPFMapPressureDefault is the fill-ratio ceiling
	// (used/max_entries) above which cilium-bpf-map-pressure fires.
	CiliumBPFMapPressureDefault = 0.85
	// CiliumNodeIPAMMinFreeDefault is the pod-IP free-ratio floor
	// below which cilium-node-ipam-exhaustion fires.
	CiliumNodeIPAMMinFreeDefault = 0.15
)

// CiliumConfigFromEnv fills c.Cilium from the CILIUM_* env vars.
// Both knobs go through GetenvFloatPositive: >1 keeps working as
// the documented "disable this check" escape and <=0 falls back to
// the default — the same contract the retired healthEnvFloat had.
func CiliumConfigFromEnv(c *Config) {
	c.Cilium = CiliumConfig{
		BPFMapPressureThreshold: envx.GetenvFloatPositive(
			"CILIUM_BPF_MAP_PRESSURE_THRESHOLD", CiliumBPFMapPressureDefault),
		NodeIPAMMinFreeRatio: envx.GetenvFloatPositive(
			"CILIUM_NODE_IPAM_MIN_FREE_RATIO", CiliumNodeIPAMMinFreeDefault),
	}
}
