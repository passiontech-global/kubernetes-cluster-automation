// circuit_metrics.go — the C1 circuit breaker's emitted-series
// bookkeeping: the WebhookCircuitBroken gauge tuples a sweep asserts
// (and the trips counter) are applied only after the config patch
// landed, so a failed patch retries next sweep without
// double-counting, and the sweep-end ledger prune drops whatever was
// not re-seen instead of pinning circuit_broken=1 forever.
package webhookguard

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// circuitMetrics applies the trip/recovery side-effects — called only
// after the config patch landed, so a failed patch retries next sweep
// without double-counting trips. A tripped series is Emitted into the
// sweep's ledger; a recovered one is deleted outright — a cleared
// breaker emits no series, not a 0, and the sweep-end ledger prune
// drops it for good.
func circuitMetrics(emitted *shared.GaugeLedger[string], kind, cfgName string, trips, recovered []string) {
	for _, n := range trips {
		metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, n).Set(1)
		emitted.Emit(kind+"/"+cfgName+"/"+n, kind, cfgName, n)
		metrics.WebhookCircuitBreakerTripsTotal.WithLabelValues(kind, cfgName).Inc()
	}
	for _, n := range recovered {
		metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfgName, n)
	}
}
