// events.go — cooldown-deduplicated Warning Event emission shared
// across probefw-based health checks so checks avoid duplicating the
// CooledDown / EmitWarningEvent / Stamp / RBAC-warning boilerplate.
package probefw

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// EmitWarningDeduped emits we once per (cd, cooldownKey, cooldown)
// window. When we.Name is empty it defaults to
// kube.TruncatedEventName(cooldownKey, cooldownKey, now); when
// we.Now is zero it defaults to now. Returns true only when the API
// Event creation succeeded and stamped cd.
func EmitWarningDeduped(
	ctx context.Context,
	cs kubernetes.Interface,
	log logr.Logger,
	cd *state.CooldownSet,
	cooldownKey string,
	cooldown time.Duration,
	now time.Time,
	we kube.WarningEvent,
) bool {
	if cd != nil && cd.CooledDown(cooldownKey, cooldown, now) {
		return false
	}
	if we.Name == "" {
		we.Name = kube.TruncatedEventName(cooldownKey, cooldownKey, now)
	}
	if we.Now.IsZero() {
		we.Now = now
	}
	if err := kube.EmitWarningEvent(ctx, cs, we); err != nil {
		log.Info("WARN: "+we.Reason+" event create failed (RBAC?)",
			"key", cooldownKey, "error", err)
		return false
	}
	if cd != nil {
		cd.Stamp(cooldownKey, now)
	}
	log.Info("EVENT: "+we.Reason, "key", cooldownKey)
	return true
}
