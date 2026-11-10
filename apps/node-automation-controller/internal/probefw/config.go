// config.go — the default values for knob groups whose env
// resolution no longer lives here: the cilium nethealth thresholds.
// The CILIUM_* resolver moved to nethealth.CiliumConfigFromEnv with
// the checks that consume it; the defaults stay beside the
// probefw.Config fields they feed so the framework keeps owning the
// knob-group registry.
package probefw

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
