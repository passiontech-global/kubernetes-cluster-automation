// Package metrics exposes Prometheus counters for the operator.
//
// hookRunErrors keeps the exact metric/label contract that
// shell-operator exposed (shell_operator_hook_run_errors_total{queue})
// so the existing PrometheusRule alerts
// (CoreDnsStaleWatchdogRunFailed, CiliumTaintReaperStale) keep working
// unchanged. reconcileErrors is the new native counterpart.
//
// The package is split by emitting domain: core.go (this file) holds
// the run-error counters, PredeclareQueue and IncError;
// apiserver.go / health.go / integration.go / operations.go hold the
// per-domain vectors AND register them — each file's init() calls
// MustRegister on exactly the vectors it declares, so adding a
// metric touches only the file that owns it. Metric names, help
// strings and label sets are unchanged from the original single-file
// layout.
//
// API convention — two shapes, by design:
//   - Exported vectors (VeleroBSLUnavailable, APIServiceUnavailable,
//     ...) are the default: modules Set/Inc/DeleteLabelValues on them
//     directly, usually through a shared.GaugeLedger that owns series
//     lifecycle. Use this when a call site is a plain
//     WithLabelValues().Set(...).
//   - Accessor functions (IncError, ObserveHealthCheck,
//     ObserveAPIBackend/ForgetAPIBackend) exist only where the call
//     carries behavior a vec cannot express: fanning one call out to
//     several series (the hook+reconcile dual counters, the
//     status+staleness pair), or lifecycle semantics beyond a Set
//     (ForgetAPIBackend's DeleteLabelValues prune). Do not add a thin
//     wrapper that merely forwards to a vec — exported access is the
//     convention, not something to hide.
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

// The queue label values are NOT listed here — cmd/manager's module
// registry is the single source of truth for the fleet's ops names,
// and setupModules calls PredeclareQueue for every row (gated or
// not) at boot. IncError below auto-creates a series on demand
// anyway; predeclaration exists only so /metrics exposes every
// module's 0-valued series before the first scrape, matching the
// eager emission shell-operator had.

// init registers ONLY the two run-error counters this file owns.
// Every other vector lives in — and is registered by — its own
// domain file's init() (apiserver.go / health.go / integration.go /
// operations.go), so this list no longer has to be edited when a
// domain adds a series.
func init() {
	ctrlmetrics.Registry.MustRegister(hookRunErrors, reconcileErrors)
}

// PredeclareQueue instantiates both error counters for module `name`
// at 0 — an empty CounterVec emits nothing on /metrics, and
// shell-operator emitted its counters eagerly, so every registered
// module's series must exist before the first scrape. setupModules
// calls this for every registry row (a gated-off module still gets
// its series — alert queries must not go absent when a module is
// disabled). `name` is the module's ops name from the registry, which
// is the legacy shell-operator queue name.
func PredeclareQueue(name string) {
	hookRunErrors.WithLabelValues(name)
	reconcileErrors.WithLabelValues(name)
}

// IncError increments both counters for module `name`. `name` must be
// the legacy shell-operator queue name (e.g. "coredns-stale-watchdog")
// so alert queries keep matching.
func IncError(name string) {
	hookRunErrors.WithLabelValues(name).Inc()
	reconcileErrors.WithLabelValues(name).Inc()
}
