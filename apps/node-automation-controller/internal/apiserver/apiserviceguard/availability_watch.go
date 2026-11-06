// availability_watch.go — duty (b) of apiservice-guard: the
// APIService availability watchdog exporting
// node_automation_apiservice_unavailable{name,service_namespace,
// service_name}=1 for every APIService holding Available=False past
// the 10m threshold. Its state (the emitted-series ledger) lives on
// availabilityWatch; shared deps are reached through snap.g.
package apiserviceguard

import (
	"context"
	"fmt"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

const (
	// apiServiceUnavailMinAge is how long an APIService must hold
	// Available=False (from the condition's lastTransitionTime)
	// before the gauge flags it — shorter-lived blips are the
	// apiserver's own aggregation churn, not an outage.
	apiServiceUnavailMinAge = 10 * time.Minute
)

// availabilityWatch owns the watchdog's per-sweep state — embedded
// in apiServiceGuard so the facade's method set (and every
// in-package test fixture built on it) is unchanged by the split.
// Shared deps (cs/dyn/now) are reached through snap.g; only the
// emitted-series ledger lives here.
type availabilityWatch struct {
	// emitted is the ledger of APIServiceUnavailable label tuples
	// ("name/service_namespace/service_name") held at =1 — a tuple
	// not re-seen this sweep gets its series deleted via
	// DeleteLabelValues (same seen-set hygiene as webhookguard's
	// brokenEmitted).
	emitted state.GaugeLedger[string]
}

// sweepAvailability consumes the same per-run snapshot — a list error
// is delivered via snap.err and aborts only this duty (the orphan
// pass already ran its own verdict).
func (w *availabilityWatch) sweepAvailability(ctx context.Context, snap *apiServiceSnapshot) error {
	g := snap.g
	log := logf.FromContext(ctx)
	if snap.err != nil {
		return fmt.Errorf("list apiservices — watchdog skipped: %w", snap.err)
	}

	now := g.now.Now()
	for i := range snap.svcs.Items {
		svc := &snap.svcs.Items[i]
		unavailSince, ok := apiServiceUnavailableSince(svc)
		if !ok || now.Sub(unavailSince) < apiServiceUnavailMinAge {
			continue
		}
		svcNs, svcName, _ := apiServiceBackend(svc)
		w.emitted.Set(metrics.APIServiceUnavailable, 1,
			svc.GetName()+"/"+svcNs+"/"+svcName,
			svc.GetName(), svcNs, svcName)
		log.Info("APIService unavailable past threshold",
			"apiservice", svc.GetName(), "service", svcNs+"/"+svcName,
			"since", unavailSince.Format(time.RFC3339))
	}

	// Prune series whose APIService recovered or vanished — a label
	// tuple that stops being re-asserted must not pin
	// apiservice_unavailable=1 forever.
	w.emitted.Prune(metrics.APIServiceUnavailable.DeleteLabelValues)
	return nil
}
