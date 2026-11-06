// config_test.go — CiliumConfigFromEnv env resolution: defaults when
// unset, overrides when set, warn-and-fallback on invalid/<=0 input,
// and the ">1 disables the check" escape hatch passing through.
package probefw

import "testing"

func TestCiliumConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "")
		var c Config
		CiliumConfigFromEnv(&c)
		if c.Cilium.BPFMapPressureThreshold != CiliumBPFMapPressureDefault {
			t.Fatalf("BPFMapPressureThreshold = %v, want %v",
				c.Cilium.BPFMapPressureThreshold, CiliumBPFMapPressureDefault)
		}
		if c.Cilium.NodeIPAMMinFreeRatio != CiliumNodeIPAMMinFreeDefault {
			t.Fatalf("NodeIPAMMinFreeRatio = %v, want %v",
				c.Cilium.NodeIPAMMinFreeRatio, CiliumNodeIPAMMinFreeDefault)
		}
	})

	t.Run("valid values override", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "0.9")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "0.25")
		var c Config
		CiliumConfigFromEnv(&c)
		if c.Cilium.BPFMapPressureThreshold != 0.9 ||
			c.Cilium.NodeIPAMMinFreeRatio != 0.25 {
			t.Fatalf("Cilium = %+v", c.Cilium)
		}
	})

	t.Run("invalid and non-positive fall back to defaults", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "junk")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "-0.5")
		var c Config
		CiliumConfigFromEnv(&c)
		if c.Cilium.BPFMapPressureThreshold != CiliumBPFMapPressureDefault ||
			c.Cilium.NodeIPAMMinFreeRatio != CiliumNodeIPAMMinFreeDefault {
			t.Fatalf("Cilium = %+v, want defaults", c.Cilium)
		}
	})

	t.Run("values over 1 keep working as the disable escape", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "1.5")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "0")
		var c Config
		CiliumConfigFromEnv(&c)
		if c.Cilium.BPFMapPressureThreshold != 1.5 {
			t.Fatalf("BPFMapPressureThreshold = %v, want 1.5 kept",
				c.Cilium.BPFMapPressureThreshold)
		}
		if c.Cilium.NodeIPAMMinFreeRatio != CiliumNodeIPAMMinFreeDefault {
			t.Fatalf("NodeIPAMMinFreeRatio = %v, want default on 0",
				c.Cilium.NodeIPAMMinFreeRatio)
		}
	})
}
