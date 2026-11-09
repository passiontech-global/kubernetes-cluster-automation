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
// instead of internal/metrics. The per-sweep phases (input gates,
// per-CRD eval, bounce dispatch) live in crd_conversion_sweep.go.
package circuitbreaker

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
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
// mutex via heal.AllowedV, UID-preconditioned eviction).
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
	s := &crdConversionSweep{
		b: b, g: g, snap: snap,
		log:         logf.FromContext(ctx),
		now:         g.Now.Now(),
		bounceSeen:  map[string]bool{},
		svcVerdicts: map[string]bool{},
		svcMissing:  map[string]bool{},
	}
	// The shared bounce ledger is stamped below for hung conversion
	// backends too — same once-per-sweep bound as Sweep.
	b.bounceAt.PruneExpired(s.now, BounceCooldown)

	proceed, err := s.loadInputs()
	if err != nil || !proceed {
		return err
	}

	s.evalCRDs(ctx)

	if !Enabled() {
		// The shared ops lever silences pod kills module-wide —
		// the gauge above stays live (detect-only, like the
		// unmeshed audit).
		return nil
	}
	s.bounceHung(ctx)
	return nil
}
