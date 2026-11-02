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

// queues are the legacy shell-operator queue names — pre-instantiated
// at 0 so /metrics always exposes every series (an empty CounterVec
// emits nothing, and shell-operator emitted its counters eagerly).
var queues = []string{
	"konnectivity-patcher", "cilium-taint-reaper", "descheduler-storm-gate",
	"node-labeler", "fluent-bit-config-roller", "coredns-stale-watchdog",
	"kubelet-liveness-reaper", "admission-webhook-guard",
	"partition-pod-evictor", "failed-jobs-janitor", "converge-trigger",
}

func init() {
	ctrlmetrics.Registry.MustRegister(hookRunErrors, reconcileErrors)
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
