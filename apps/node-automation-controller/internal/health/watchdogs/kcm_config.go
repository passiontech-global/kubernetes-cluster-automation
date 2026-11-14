// kcm_config.go — the HEALTH_* env resolution for the
// kcm-workqueue-watchdog check (C6): the leader-election Lease max
// age that bounds "still renewing" and the freeze persistence
// window a stalled reconcile must exceed before the gauge fires.
package watchdogs

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// KCMConfig — kcm-workqueue-watchdog (C6) knobs.
type KCMConfig struct {
	LeaseMaxAge  time.Duration // HEALTH_KCM_LEASE_MAX_AGE
	FreezeMinAge time.Duration // HEALTH_KCM_FREEZE_MIN_AGE
}

// KCMConfigFromEnv resolves the kcm-workqueue-watchdog knobs.
func KCMConfigFromEnv() KCMConfig {
	return KCMConfig{
		LeaseMaxAge:  envx.GetenvDuration("HEALTH_KCM_LEASE_MAX_AGE", 30*time.Second),
		FreezeMinAge: envx.GetenvDuration("HEALTH_KCM_FREEZE_MIN_AGE", 10*time.Minute),
	}
}
