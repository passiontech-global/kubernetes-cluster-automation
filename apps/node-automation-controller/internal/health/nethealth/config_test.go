// config_test.go — CiliumConfigFromEnv env resolution: defaults when
// unset, overrides when set, warn-and-fallback on invalid/<=0 input,
// and the ">1 disables the check" escape hatch passing through.
package nethealth

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
)

func TestCiliumConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "")
		c := CiliumConfigFromEnv()
		if c.BPFMapPressureThreshold != probefw.CiliumBPFMapPressureDefault {
			t.Fatalf("BPFMapPressureThreshold = %v, want %v",
				c.BPFMapPressureThreshold, probefw.CiliumBPFMapPressureDefault)
		}
		if c.NodeIPAMMinFreeRatio != probefw.CiliumNodeIPAMMinFreeDefault {
			t.Fatalf("NodeIPAMMinFreeRatio = %v, want %v",
				c.NodeIPAMMinFreeRatio, probefw.CiliumNodeIPAMMinFreeDefault)
		}
	})

	t.Run("valid values override", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "0.9")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "0.25")
		c := CiliumConfigFromEnv()
		if c.BPFMapPressureThreshold != 0.9 ||
			c.NodeIPAMMinFreeRatio != 0.25 {
			t.Fatalf("Cilium = %+v", c)
		}
	})

	t.Run("invalid and non-positive fall back to defaults", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "junk")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "-0.5")
		c := CiliumConfigFromEnv()
		if c.BPFMapPressureThreshold != probefw.CiliumBPFMapPressureDefault ||
			c.NodeIPAMMinFreeRatio != probefw.CiliumNodeIPAMMinFreeDefault {
			t.Fatalf("Cilium = %+v, want defaults", c)
		}
	})

	t.Run("values over 1 keep working as the disable escape", func(t *testing.T) {
		t.Setenv("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", "1.5")
		t.Setenv("CILIUM_NODE_IPAM_MIN_FREE_RATIO", "0")
		c := CiliumConfigFromEnv()
		if c.BPFMapPressureThreshold != 1.5 {
			t.Fatalf("BPFMapPressureThreshold = %v, want 1.5 kept",
				c.BPFMapPressureThreshold)
		}
		if c.NodeIPAMMinFreeRatio != probefw.CiliumNodeIPAMMinFreeDefault {
			t.Fatalf("NodeIPAMMinFreeRatio = %v, want default on 0",
				c.NodeIPAMMinFreeRatio)
		}
	})
}

// LinkerdConfigFromEnv resolves the LINKERD_* knobs through envx.Gate
// — enabled unless the value is exactly "false" (the always-on
// convention the ported checks kept).
func TestLinkerdConfigFromEnv(t *testing.T) {
	t.Run("enabled by default", func(t *testing.T) {
		t.Setenv("LINKERD_OUTLIER_EVICT_ENABLED", "")
		if c := LinkerdConfigFromEnv(); !c.OutlierEvictEnabled {
			t.Fatal("OutlierEvictEnabled = false on unset env")
		}
	})

	t.Run("only exact false disables", func(t *testing.T) {
		for _, v := range []string{"false", "FALSE", "0", "no", "off"} {
			t.Setenv("LINKERD_OUTLIER_EVICT_ENABLED", v)
			got := LinkerdConfigFromEnv().OutlierEvictEnabled
			want := v != "false"
			if got != want {
				t.Fatalf("value %q -> %v, want %v", v, got, want)
			}
		}
	})
}
