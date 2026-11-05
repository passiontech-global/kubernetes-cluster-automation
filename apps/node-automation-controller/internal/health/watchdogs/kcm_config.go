// kcm_config.go — the HEALTH_* env resolution for the
// kcm-workqueue-watchdog check (C6): the leader-election Lease max
// age that bounds "still renewing" and the freeze persistence
// window a stalled reconcile must exceed before the gauge fires.
// Resolved once at sweep Setup —
// clusterhealthprobes.healthProbeConfigFromEnv delegates the
// watchdog knobs here and keeps only the sweep-level timeouts
// itself.
package watchdogs

import (
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// KCMConfigFromEnv fills c.KCM — the kcm-workqueue-watchdog knobs —
// from the HEALTH_* env vars.
func KCMConfigFromEnv(c *probefw.Config) {
	c.KCM = probefw.KCMConfig{
		// KCM leader-election defaults are LeaseDuration 15s,
		// RenewDeadline 10s, RetryPeriod ~2s, so a live holder's
		// renewTime is never more than a few seconds old. 30s —
		// 2× the lease duration — bounds "still renewing" with
		// margin for apiserver latency; anything older means
		// the holder is gone (a dead KCM, not a frozen one).
		LeaseMaxAge: shared.GetenvDuration("HEALTH_KCM_LEASE_MAX_AGE", 30*time.Second),
		// A freeze signature must persist this long before the
		// gauge fires — a healthy reconcile legitimately lags a
		// spec write by a sync period or two.
		FreezeMinAge: shared.GetenvDuration("HEALTH_KCM_FREEZE_MIN_AGE", 10*time.Minute),
	}
}
