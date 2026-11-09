// kcm_config_test.go — KCMConfigFromEnv env resolution: the
// leader-election Lease max age and freeze persistence window
// default when unset, honor overrides, and warn-and-fallback on
// invalid or sub-second durations (envx.GetenvDuration's floor).
package watchdogs

import (
	"testing"
	"time"
)

func TestKCMConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv("HEALTH_KCM_LEASE_MAX_AGE", "")
		t.Setenv("HEALTH_KCM_FREEZE_MIN_AGE", "")
		c := KCMConfigFromEnv()
		if c.LeaseMaxAge != 30*time.Second || c.FreezeMinAge != 10*time.Minute {
			t.Fatalf("KCM = %+v, want 30s/10m", c)
		}
	})

	t.Run("valid values override", func(t *testing.T) {
		t.Setenv("HEALTH_KCM_LEASE_MAX_AGE", "45s")
		t.Setenv("HEALTH_KCM_FREEZE_MIN_AGE", "20m")
		c := KCMConfigFromEnv()
		if c.LeaseMaxAge != 45*time.Second || c.FreezeMinAge != 20*time.Minute {
			t.Fatalf("KCM = %+v", c)
		}
	})

	t.Run("invalid and sub-second durations fall back", func(t *testing.T) {
		t.Setenv("HEALTH_KCM_LEASE_MAX_AGE", "junk")
		t.Setenv("HEALTH_KCM_FREEZE_MIN_AGE", "500ms")
		c := KCMConfigFromEnv()
		if c.LeaseMaxAge != 30*time.Second || c.FreezeMinAge != 10*time.Minute {
			t.Fatalf("KCM = %+v, want defaults on invalid input", c)
		}
	})
}
