// kcm_config.go — the HEALTH_* env resolution for the
// kcm-workqueue-watchdog check (C6): the leader-election Lease max
// age that bounds "still renewing" and the freeze persistence
// window a stalled reconcile must exceed before the gauge fires.
// Resolved once at sweep Setup —
// clusterhealthprobes.healthProbeConfigFromEnv assigns the returned
// KCMConfig into cfg.KCM and keeps only the sweep-level timeouts
// itself.
package watchdogs

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// KCMConfigFromEnv resolves the kcm-workqueue-watchdog knobs — the
// HEALTH_* env vars backing cfg.KCM — as the sub-struct the caller
// assigns.
func KCMConfigFromEnv() probefw.KCMConfig {
	return probefw.KCMConfig{
		// KCM leader-election defaults are LeaseDuration 15s,
		// RenewDeadline 10s, RetryPeriod ~2s, so a live holder's
		// renewTime is never more than a few seconds old. 30s —
		// 2× the lease duration — bounds "still renewing" with
		// margin for apiserver latency; anything older means
		// the holder is gone (a dead KCM, not a frozen one).
		LeaseMaxAge: envx.GetenvDuration("HEALTH_KCM_LEASE_MAX_AGE", 30*time.Second),
		// A freeze signature must persist this long before the
		// gauge fires — a healthy reconcile legitimately lags a
		// spec write by a sync period or two.
		FreezeMinAge: envx.GetenvDuration("HEALTH_KCM_FREEZE_MIN_AGE", 10*time.Minute),
	}
}
