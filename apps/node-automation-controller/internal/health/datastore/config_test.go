// config_test.go — coverage for the datastore knobs' env resolution:
// defaults when unset, parsed overrides, and the warn-and-fallback
// contract for unparseable or sub-second values.
package datastore

import (
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		got := ConfigFromEnv()
		if got.CNPGUnhealthyMinAge != CNPGUnhealthyMinAgeDefault {
			t.Fatalf("CNPGUnhealthyMinAge = %v, want default %v",
				got.CNPGUnhealthyMinAge, CNPGUnhealthyMinAgeDefault)
		}
		if got.PVCResizeStallMinAge != PVCResizeStallMinAgeDefault {
			t.Fatalf("PVCResizeStallMinAge = %v, want default %v",
				got.PVCResizeStallMinAge, PVCResizeStallMinAgeDefault)
		}
	})

	t.Run("parsed overrides", func(t *testing.T) {
		t.Setenv("HEALTH_CNPG_UNHEALTHY_MIN_AGE", "20m")
		t.Setenv("HEALTH_PVC_RESIZE_STALL_MIN_AGE", "45m")
		got := ConfigFromEnv()
		if got.CNPGUnhealthyMinAge != 20*time.Minute {
			t.Fatalf("CNPGUnhealthyMinAge = %v, want 20m", got.CNPGUnhealthyMinAge)
		}
		if got.PVCResizeStallMinAge != 45*time.Minute {
			t.Fatalf("PVCResizeStallMinAge = %v, want 45m", got.PVCResizeStallMinAge)
		}
	})

	t.Run("invalid and sub-second fall back to defaults", func(t *testing.T) {
		t.Setenv("HEALTH_CNPG_UNHEALTHY_MIN_AGE", "not-a-duration")
		t.Setenv("HEALTH_PVC_RESIZE_STALL_MIN_AGE", "500ms")
		got := ConfigFromEnv()
		if got.CNPGUnhealthyMinAge != CNPGUnhealthyMinAgeDefault {
			t.Fatalf("unparseable CNPGUnhealthyMinAge = %v, want default", got.CNPGUnhealthyMinAge)
		}
		if got.PVCResizeStallMinAge != PVCResizeStallMinAgeDefault {
			t.Fatalf("sub-second PVCResizeStallMinAge = %v, want default", got.PVCResizeStallMinAge)
		}
	})
}
