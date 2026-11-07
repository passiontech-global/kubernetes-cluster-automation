// crd_conversion.go — the CRD conversion-webhook backend health
// check, split out of circuit_breaker.go so the admission-trip duty
// and this one each read on their own: a dead conversion backend
// has no failurePolicy to trip — every CR read for the whole API
// group errors — so the sweep only exports
// node_automation_crd_conversion_webhook_unhealthy per CRD
// (missing_service|zero_endpoints|tls_probe_failed) and bounces the
// oldest wedged backing pod through the same BounceCooldown ledger
// and maintenance-mutex gate as the admission path. The gauge is a
// single-check series, so it lives here (colocated var + init)
// instead of internal/metrics.
package circuitbreaker

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// ---------------------------------------------------------------------------
// CRD conversion-webhook backend health — the same dead-backend
// failure modes the breaker covers for admission webhooks, but with
// no failurePolicy knob at all: a dead conversion backend errors
// every CR read for the whole API group.
// ---------------------------------------------------------------------------

// CRDReason* are the reason label values of
// CRDConversionWebhookUnhealthy — the three measurable dead-backend
// signatures.
const (
	// CRDReasonMissingService: the conversion clientConfig points at
	// a Service that does not exist.
	CRDReasonMissingService = "missing_service"
	// CRDReasonZeroEndpoints: the Service exists but the endpoint
	// census reports 0 effective-Ready endpoints (endpoints on
	// partitioned nodes count as dead, same as the breaker's math).
	CRDReasonZeroEndpoints = "zero_endpoints"
	// CRDReasonTLSProbeFailed: Ready endpoints exist but EVERY probed
	// IP failed the TCP+TLS handshake — wedged pods, which the sweep
	// bounces.
	CRDReasonTLSProbeFailed = "tls_probe_failed"
)

// CRDConversionWebhookUnhealthy marks (1) each CustomResourceDefinition
// whose spec.conversion webhook backend is measurably broken — a
// single-check series, so it lives here (colocated var + init)
// instead of internal/metrics. reason carries the verdict
// (missing_service|zero_endpoints|tls_probe_failed); the series
// disappears once the backend is healthy again.
var CRDConversionWebhookUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_crd_conversion_webhook_unhealthy",
	Help: "1 while the CRD's spec.conversion webhook backend is unhealthy (missing_service|zero_endpoints|tls_probe_failed).",
}, []string{"crd", "service", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(CRDConversionWebhookUnhealthy)
}

// crdConversionKey is the exact label tuple of the
// CRDConversionWebhookUnhealthy gauge — the GaugeLedger key, same
// contract as the WebhookCircuitBroken ledger.
type crdConversionKey struct{ crd, service, reason string }

// SweepCRDConversionBackends health-checks every CRD whose
// spec.conversion.strategy is Webhook and whose clientConfig targets
// an in-cluster Service — one of the four independent duties behind
// the admission-webhook-guard sweep. The failure modes are the breaker's three
// dead-backend signatures, but a dead CONVERSION backend is worse
// than a dead admission one: there is no failurePolicy to trip, so
// every CR read for the whole API group errors while it lasts. The
// sweep therefore only exports
// node_automation_crd_conversion_webhook_unhealthy per CRD — never
// touches the CRD object — and bounces the oldest wedged backend pod
// so the controller recreates it serving (the same stage-1 heal as
// the admission path: BounceCooldown, the shared maintenance
// mutex via heal.AllowedV, UID-preconditioned delete).
//
// Series hygiene: a complete sweep emits the current tuple per
// unhealthy CRD and prunes whatever was not re-seen — a stale
// reason tuple (missing_service → zero_endpoints when the Service
// comes back empty) or a recovered backend must not pin the alert.
// An unverifiable sweep carries the last verdict forward — a
// transient CRD list failure or a blind census is "can't tell", not
// "clean".
func (b *Breaker) SweepCRDConversionBackends(ctx context.Context,
	snap *guardstate.Snapshot) error {
	b.crdUnhealthyEmitted.Begin() // drop any aborted sweep's leftover emissions
	g := snap.G
	log := logf.FromContext(ctx)
	now := g.Now.Now()
	// The shared bounce ledger is stamped below for hung conversion
	// backends too — same once-per-sweep bound as Sweep.
	b.bounceAt.PruneExpired(now, BounceCooldown)

	carryForward := func() {
		for k, lv := range b.crdUnhealthyEmitted.Last() {
			b.crdUnhealthyEmitted.Emit(k, lv...)
		}
		b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)
	}

	if snap.CRDErr != nil {
		// API flap — "can't read the surface" fails closed: carry
		// the series forward and surface the error.
		carryForward()
		return fmt.Errorf("list customresourcedefinitions — conversion webhook health skipped: %w", snap.CRDErr)
	}
	ready, err := snap.ReadyCounts()
	if err != nil {
		// The breaker reports the same census failure as ITS error —
		// re-reporting it here would double-count. Defer quietly and
		// keep the last verdict alive — UNLESS the breaker is
		// levered off this cycle, in which case nobody else reports
		// it and the failure would be invisible.
		carryForward()
		if !Enabled() {
			return fmt.Errorf("endpoint/node census — conversion webhook health skipped: %w", err)
		}
		return nil
	}

	// svcVerdict caches each backend Service's existence check for the
	// sweep — a single conversion server commonly backs an operator's
	// whole API group (dozens of CRDs), so re-Getting the same Service
	// per CRD is pure apiserver churn. Inconclusive gets (flap,
	// timeout) are NOT cached: a transient error must not freeze the
	// verdict for the rest of the sweep.
	svcVerdicts := map[string]bool{} // svcKey -> confirmed present
	svcMissing := map[string]bool{}  // svcKey -> confirmed NotFound
	svcExists := func(svcKey, ns, name string) (missing, exists bool, err error) {
		if svcVerdicts[svcKey] {
			return false, true, nil
		}
		if svcMissing[svcKey] {
			return true, false, nil
		}
		_, gerr := g.CS.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(gerr):
			svcMissing[svcKey] = true
			return true, false, nil
		case gerr != nil:
			return false, false, gerr
		}
		svcVerdicts[svcKey] = true
		return false, true, nil
	}

	var hung []string
	bounceSeen := map[string]bool{}
	for i := range snap.CRDs {
		crd := &snap.CRDs[i]
		svcKey, svcNS, svcName, ok := guardstate.CRDConversionServiceKey(crd)
		if !ok {
			continue // no webhook conversion or a URL backend — unmeasurable
		}
		reason := ""
		missing, _, err := svcExists(svcKey, svcNS, svcName)
		switch {
		case missing:
			reason = CRDReasonMissingService
			log.Info("UNHEALTHY: CRD conversion webhook backend Service missing",
				"crd", crd.GetName(), "service", svcKey)
		case err != nil:
			// Can't verify — carry this CRD's last verdict forward
			// rather than flap; absorbed sub-failure, sweep
			// continues.
			metrics.IncError(g.Queue)
			log.Error(err, "conversion webhook backend Service get failed",
				"crd", crd.GetName(), "service", svcKey)
			for k, lv := range b.crdUnhealthyEmitted.Last() {
				if k.crd == crd.GetName() {
					b.crdUnhealthyEmitted.Emit(k, lv...)
				}
			}
			continue
		case ready.Effective[svcKey] == 0:
			reason = CRDReasonZeroEndpoints
			log.Info("UNHEALTHY: CRD conversion webhook backend has 0 effective-ready endpoints",
				"crd", crd.GetName(), "service", svcKey)
		case ready.Probed[svcKey] && !ready.Responsive[svcKey]:
			reason = CRDReasonTLSProbeFailed
			log.Info("UNHEALTHY: CRD conversion webhook backend fails TCP+TLS probe on every endpoint — pods wedged",
				"crd", crd.GetName(), "service", svcKey)
			if !bounceSeen[svcKey] {
				bounceSeen[svcKey] = true
				hung = append(hung, svcKey)
			}
		}
		if reason == "" {
			continue
		}
		k := crdConversionKey{crd: crd.GetName(), service: svcKey, reason: reason}
		b.crdUnhealthyEmitted.Set(CRDConversionWebhookUnhealthy, 1,
			k, k.crd, k.service, k.reason)
	}
	b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)

	if !Enabled() {
		// The shared ops lever silences pod kills module-wide —
		// the gauge above stays live (detect-only, like the
		// unmeshed audit).
		return nil
	}
	for _, svcKey := range hung {
		// heal.AllowedV folds the BounceCooldown per-service cooldown AND the
		// maintenance mutex into one fail-closed preamble; &g.Verdict
		// memoizes the mutex across services (and shares it with the
		// admission bounce + unmeshed paths) instead of paying three
		// API reads per service.
		proceed, unverifiable := heal.AllowedV(ctx, log, &g.Verdict,
			g.CS, g.Dyn, &b.bounceAt, svcKey, BounceCooldown, now)
		if unverifiable {
			metrics.IncError(g.Queue)
			continue
		}
		if !proceed {
			continue
		}
		b.bounceOldestPod(ctx, snap, svcKey, ready.BackingPods[svcKey], now)
	}
	return nil
}
