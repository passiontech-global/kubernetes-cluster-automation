// Package metrics exposes Prometheus counters for the operator.
//
// hookRunErrors keeps the exact metric/label contract that
// shell-operator exposed (shell_operator_hook_run_errors_total{queue})
// so the existing PrometheusRule alerts
// (CoreDnsStaleWatchdogRunFailed, CiliumTaintReaperStale) keep working
// unchanged. reconcileErrors is the new native counterpart.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var hookRunErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "shell_operator_hook_run_errors_total",
	Help: "Module run errors (shell-operator compatible counter).",
}, []string{"queue"})

var reconcileErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_reconcile_errors_total",
	Help: "Module run errors (node-automation-controller native counter).",
}, []string{"controller"})

// apiserver-endpoint-guard per-backend gauges — the wedge signal
// itself, so alerting can fire on rv_gap growth BEFORE a quarantine
// happens. Label is the backend IP; -1 marks a failed probe cycle.
var apiBackendRVGap = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiserver_rv_gap",
	Help: "Per-apiserver-backend live_rv - cache_rv (watch-cache wedge signal; -1 on probe failure).",
}, []string{"backend"})

var apiBackendQuarantined = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiserver_quarantined",
	Help: "1 while the backend IP is quarantined out of default/Endpoints and EndpointSlice kubernetes.",
}, []string{"backend"})

// queues are the legacy shell-operator queue names — pre-instantiated
// at 0 so /metrics always exposes every series (an empty CounterVec
// emits nothing, and shell-operator emitted its counters eagerly).
var queues = []string{
	"konnectivity-patcher", "cilium-taint-reaper", "descheduler-storm-gate",
	"node-labeler", "fluent-bit-config-roller", "coredns-stale-watchdog",
	"kubelet-liveness-reaper", "admission-webhook-guard",
	"partition-pod-evictor", "failed-jobs-janitor", "converge-trigger",
	// remediation modules (v0.2.0)
	"dead-node-sweeper", "helmrelease-unlocker", "externalsecret-nudge",
	"evicted-pod-janitor", "cronjob-catchup", "certmanager-reaper",
	"cilium-identity-auditor", "csr-watcher",
	// watch-cache wedge guard
	"apiserver-endpoint-guard",
}

func init() {
	ctrlmetrics.Registry.MustRegister(hookRunErrors, reconcileErrors,
		apiBackendRVGap, apiBackendQuarantined)
	for _, q := range queues {
		hookRunErrors.WithLabelValues(q)
		reconcileErrors.WithLabelValues(q)
	}
}

// IncError increments both counters for module `name`. `name` must be
// the legacy shell-operator queue name (e.g. "coredns-stale-watchdog")
// so alert queries keep matching.
func IncError(name string) {
	hookRunErrors.WithLabelValues(name).Inc()
	reconcileErrors.WithLabelValues(name).Inc()
}

// ObserveAPIBackend records one probe cycle of the
// apiserver-endpoint-guard for backend `ip`: rvGap is live_rv-cache_rv
// (-1 on probe failure) and quarantined marks whether the IP is
// currently pulled out of default/kubernetes.
func ObserveAPIBackend(ip string, rvGap float64, quarantined bool) {
	apiBackendRVGap.WithLabelValues(ip).Set(rvGap)
	v := 0.0
	if quarantined {
		v = 1
	}
	apiBackendQuarantined.WithLabelValues(ip).Set(v)
}

// ForgetAPIBackend prunes the per-backend series when an IP leaves the
// controller set (controller decommissioned) so /metrics does not leak
// stale label values.
func ForgetAPIBackend(ip string) {
	apiBackendRVGap.DeleteLabelValues(ip)
	apiBackendQuarantined.DeleteLabelValues(ip)
}
