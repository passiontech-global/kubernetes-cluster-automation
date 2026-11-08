// health.go — the kuberhealthy-compatible check gauges plus the
// health-domain series that stay here because they are shared or
// ops-contract surface. Single-check series are colocated instead:
// a check whose vector only it emits declares and registers it in
// its own file's init() under internal/health/<sub>/ (the
// node_automation_image_pull_backoff convention — see core.go's
// API-convention note), so this file holds only the kuberhealthy
// reporter pair and the multi-consumer heal counter.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// cluster-health-probes gauges — the EXACT series kuberhealthy
// exported for the five ported HealthChecks, so the
// KuberhealthyCheckFailed / KuberhealthyCheckStale PrometheusRule
// alerts (and any dashboard keyed on check=<HealthCheck name>) keep
// firing with no PromQL change. The namespace label stays the literal
// "kuberhealthy" — the ns the HealthCheck CRs lived in — because the
// alert annotations render {{ $labels.namespace }}.
const healthCheckMetricNamespace = "kuberhealthy"

var healthCheckStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "kuberhealthy_check",
	Help: "Kuberhealthy-compatible check result (status=OK|FAIL) emitted by the in-process prober.",
}, []string{"check", "namespace", "status"})

var healthCheckSecondsSinceSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "kuberhealthy_check_seconds_since_success",
	Help: "Seconds since the check last reported OK (kuberhealthy-compatible).",
}, []string{"check", "namespace"})

// ControlPlanePodHealsTotal counts control-plane/operator pods deleted
// by the cluster-health mesh watchdogs — cilium-operator on
// CiliumIPAMExhausted (W8-NM2), linkerd-destination/identity on the
// wedged-watch signature (W8-NM3), and db operator pods deleted to
// force master re-election for a masterless StatefulSet (W4
// stateful-masterless extension). Shared: several health packages
// (and probefw's DeletePodHeal helper) all Inc it under their own
// component label, so it cannot colocate into one check file.
var ControlPlanePodHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_controlplane_pod_heals_total",
	Help: "Control-plane/operator pods deleted to force re-election or resync, by component.",
}, []string{"component"})

// healthCollectors lists every vector declared in this file, in
// declaration order; the single init() below registers the table.
var healthCollectors = []prometheus.Collector{
	healthCheckStatus, healthCheckSecondsSinceSuccess,
	ControlPlanePodHealsTotal,
}

func init() {
	for _, c := range healthCollectors {
		ctrlmetrics.Registry.MustRegister(c)
	}
}

// ObserveHealthCheck records one result of a ported kuberhealthy check
// under its original HealthCheck name: the status=OK|FAIL gauges
// mirror kuberhealthy's output exactly (a pass sets OK=1/FAIL=0, a
// fail flips them) and secondsSinceSuccess feeds the stale-check
// alert — the caller tracks lastSuccess and passes now-lastSuccess
// (0 on a pass, growing while the check keeps failing).
func ObserveHealthCheck(check string, ok bool, secondsSinceSuccess float64) {
	okV, failV := 0.0, 1.0
	if ok {
		okV, failV = 1.0, 0.0
	}
	healthCheckStatus.WithLabelValues(check, healthCheckMetricNamespace, "OK").Set(okV)
	healthCheckStatus.WithLabelValues(check, healthCheckMetricNamespace, "FAIL").Set(failV)
	healthCheckSecondsSinceSuccess.
		WithLabelValues(check, healthCheckMetricNamespace).Set(secondsSinceSuccess)
}
