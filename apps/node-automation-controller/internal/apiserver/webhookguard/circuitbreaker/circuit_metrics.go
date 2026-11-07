// circuit_metrics.go — the C1 circuit breaker's emitted-series
// bookkeeping: the WebhookCircuitBroken gauge tuples a sweep asserts
// (and the trips counter) are applied only after the config patch
// landed, so a failed patch retries next sweep without
// double-counting, the carry-forward re-asserts the last confirmed
// tuples while the post-patch annotation is unverifiable, and the
// sweep-end ledger prune drops whatever was not re-seen instead of
// pinning circuit_broken=1 forever.
package circuitbreaker

import (
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// circuitMetrics applies the trip/recovery side-effects — called only
// after the config patch landed (or, on the nil-payload path, after
// the live state verified no write was needed), so a failed patch
// retries next sweep without double-counting trips. A tripped or
// still-broken series is Emitted into the sweep's ledger; a
// recovered one is deleted outright — a cleared breaker emits no
// series, not a 0, and the sweep-end ledger prune drops it for
// good.
func circuitMetrics(emitted *state.GaugeLedger[string], kind, cfgName string,
	trips, recovered, stillBroken []string) {
	for _, n := range trips {
		emitted.Set(metrics.WebhookCircuitBroken, 1,
			kind+"/"+cfgName+"/"+n, kind, cfgName, n)
		metrics.WebhookCircuitBreakerTripsTotal.WithLabelValues(kind, cfgName).Inc()
	}
	for _, n := range stillBroken {
		emitted.Set(metrics.WebhookCircuitBroken, 1,
			kind+"/"+cfgName+"/"+n, kind, cfgName, n)
	}
	for _, n := range recovered {
		metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfgName, n)
	}
}

// carryBrokenForward re-asserts last sweep's WebhookCircuitBroken
// tuples for one config after its patch failed — the same
// carry-forward the CRD conversion sweep runs on an unverifiable
// read: a failed patch leaves the annotation (and the truth the
// series reports) at its last confirmed state, so the sweep-end
// prune must not flap a still-broken series off.
func (b *Breaker) carryBrokenForward(kind, cfgName string) {
	prefix := kind + "/" + cfgName + "/"
	for k, lv := range b.brokenEmitted.Last() {
		if strings.HasPrefix(k, prefix) {
			b.brokenEmitted.Emit(k, lv...)
		}
	}
}
