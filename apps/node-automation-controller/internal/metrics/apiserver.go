// apiserver.go — series emitted by the internal/apiserver modules:
// apiserver-endpoint-guard (per-backend wedge gauges), apiservice-
// guard (aggregated API availability + the namespace-terminating-wedged unblock heals)
// and admission-webhook-guard (circuit breaker + unmeshed-pod
// auditor). Var order and comments follow the original metrics.go
// layout.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

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

// apiBackendJWKSKIDSkew marks (1) a backend whose /openid/v1/jwks kid
// set disagrees with the healthy-backend majority for the streak
// threshold — sa.pub/sa.key rotation skew surfaces as random 401s
// across the HAProxy pool (jwks-kid-skew).
var apiBackendJWKSKIDSkew = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiserver_jwks_kid_skew",
	Help: "1 while the backend's JWKS kid set mismatches the control-plane majority (SA signer-key skew).",
}, []string{"backend"})

// ---------------------------------------------------------------------------
// Self-healing / gray-failure defense metrics (Quick-Wins + C1-C6).
// Exported so the module packages under internal/<domain>/ drive the
// vectors directly.
// ---------------------------------------------------------------------------

// WebhookCircuitBroken marks (1) each sub-webhook currently patched to
// failurePolicy=Ignore by the admission-webhook circuit breaker (C1).
// Labels: webhook config kind, config name, sub-webhook name.
var WebhookCircuitBroken = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_webhook_circuit_broken",
	Help: "1 while the named sub-webhook is circuit-broken (failurePolicy patched to Ignore).",
}, []string{"kind", "name", "webhook"})

// WebhookCircuitBreakerTripsTotal counts how many times the circuit
// breaker tripped per webhook config.
var WebhookCircuitBreakerTripsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_webhook_circuit_breaker_trips_total",
	Help: "Circuit-breaker trips per webhook config.",
}, []string{"kind", "name"})

// BootWebhookFailOpenTotal counts medik8s boot-path validating webhook
// entries enforced to failurePolicy=Ignore by the bootwebhooks duty —
// incremented only when the patch landed, so it also counts post-OLM
// drift re-heals. Labels: webhook config name, sub-webhook name.
var BootWebhookFailOpenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_boot_webhook_failopen_total",
	Help: "Medik8s boot-path webhook entries enforced to failurePolicy=Ignore.",
}, []string{"name", "webhook"})

// WebhookMissingCriticalNSExclusion marks (1) live admission sub-webhooks
// with failurePolicy=Fail whose namespaceSelector still matches any of the
// critical self-healing namespaces (kube-system, kube-node-lease, node-ops,
// medik8s) — catches Helm/operator-installed webhooks invisible to static
// check-webhook-guard.sh (critical-ns-audit; kube-node-lease added later — its
// leases ARE the kubelet node heartbeat).
var WebhookMissingCriticalNSExclusion = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_webhook_missing_critical_ns_exclusion",
	Help: "1 while the fail-closed sub-webhook's namespaceSelector matches kube-system, kube-node-lease, node-ops, or medik8s.",
}, []string{"kind", "name", "webhook"})

// WebhookHeartbeatResourceExposed marks (1) per matched rule resource for
// each live fail-closed admission sub-webhook whose rules[].resources
// intercept a node/pod lifecycle heartbeat resource (nodes/status,
// pods/status, pods/eviction, leases — or a wildcard covering them) while
// its namespaceSelector still matches a critical self-healing namespace
// On a match: the webhook's own outage then wedges node heartbeats and
// every drain cluster-wide. The resource label carries the offending
// rule literal (wildcards stay wildcards, matching the static guard's
// blocked_resources grammar).
var WebhookHeartbeatResourceExposed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_webhook_heartbeat_resource_exposed",
	Help: "1 while the fail-closed webhook's rules intercept nodes/status, pods/status, pods/eviction, or leases and its namespaceSelector still matches the critical self-healing namespaces.",
}, []string{"kind", "name", "webhook", "resource"})

// CRDConversionWebhookUnhealthy marks (1) each CustomResourceDefinition
// whose spec.conversion webhook backend is measurably broken — a
// single-check series of the admission-webhook-guard CRD conversion
// breaker (Wave 5.1 consolidated out of the module file into the
// apiserver domain file). reason carries the verdict
// (missing_service|zero_endpoints|tls_probe_failed); the series
// disappears once the backend is healthy again.
var CRDConversionWebhookUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_crd_conversion_webhook_unhealthy",
	Help: "1 while the CRD's spec.conversion webhook backend is unhealthy (missing_service|zero_endpoints|tls_probe_failed).",
}, []string{"crd", "service", "reason"})

// ---------------------------------------------------------------------------
// Operations metrics — cluster-health check series.
// ---------------------------------------------------------------------------

// APIServiceUnavailable marks (1) aggregated APIServices whose
// Available=False condition persisted past the guard threshold
// (apiservice-guard, 2.3).
var APIServiceUnavailable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiservice_unavailable",
	Help: "1 while the aggregated APIService reports Available=False past the audit threshold.",
}, []string{"name", "service_namespace", "service_name"})

// UnmeshedPods marks (1) Running Pods that should carry a linkerd-proxy
// sidecar but do not (unmeshed-pod-auditor, 2.2).
var UnmeshedPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_unmeshed_pods",
	Help: "1 while the Pod runs without the injected linkerd-proxy sidecar despite injection being enabled.",
}, []string{"namespace", "pod"})

// UnmeshedPodsRecreatedTotal counts unmeshed Pods deleted for
// re-creation once the injector webhook is healthy again.
var UnmeshedPodsRecreatedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_unmeshed_pods_recreated_total",
	Help: "Unmeshed Pods deleted so their controller recreates them with the sidecar.",
}, []string{"namespace"})

// ---------------------------------------------------------------------------
// Later self-healing metrics grouped by owning module (kine-bloat-guard/backup-posture-audit/
// externalsecret-storm-guard/cloudflared-wedge-heal/velero-inflight-audit/namespace-terminating-wedged).
// ---------------------------------------------------------------------------

// APIServiceUnblockHealsTotal counts dead APIService heals forced
// through the namespace-skip gate by the apiservice guard (namespace-terminating-wedged):
// an APIService in a normally-skipped namespace that stayed
// Available=False >=15m while a namespace sat Terminating >=15m with
// references to its API group.
var APIServiceUnblockHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_apiservice_unblock_heals_total",
	Help: "APIService heals forced past the skip-namespace gate, by namespace and reason.",
}, []string{"namespace", "reason"})

// apiserverCollectors lists every vector declared in this file, in
// declaration order; the single init() below registers the table, so
// registration order stays byte-stable and adding a metric touches
// only this file.
var apiserverCollectors = []prometheus.Collector{
	apiBackendRVGap, apiBackendQuarantined, apiBackendJWKSKIDSkew,
	WebhookCircuitBroken, WebhookCircuitBreakerTripsTotal,
	BootWebhookFailOpenTotal,
	WebhookMissingCriticalNSExclusion, WebhookHeartbeatResourceExposed,
	APIServiceUnavailable,
	UnmeshedPods, UnmeshedPodsRecreatedTotal,
	APIServiceUnblockHealsTotal,
	CRDConversionWebhookUnhealthy,
}

func init() {
	for _, c := range apiserverCollectors {
		ctrlmetrics.Registry.MustRegister(c)
	}
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

// ObserveAPIBackendJWKSSkew records this cycle's JWKS kid-set
// majority verdict for backend `ip` (jwks-kid-skew).
func ObserveAPIBackendJWKSSkew(ip string, skewed bool) {
	v := 0.0
	if skewed {
		v = 1
	}
	apiBackendJWKSKIDSkew.WithLabelValues(ip).Set(v)
}

// ForgetAPIBackend prunes the per-backend series when an IP leaves the
// controller set (controller decommissioned) so /metrics does not leak
// stale label values.
func ForgetAPIBackend(ip string) {
	apiBackendRVGap.DeleteLabelValues(ip)
	apiBackendQuarantined.DeleteLabelValues(ip)
	apiBackendJWKSKIDSkew.DeleteLabelValues(ip)
}
