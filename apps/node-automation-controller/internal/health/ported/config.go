// config.go — the HEALTH_* env resolution for the ported
// kuberhealthy checks: the dns-status-internal hostnames, the
// http-content-check target URL and expected body, the
// pod-restarts/pod-status namespace, restart ceiling and skip
// window, and the resource-quota threshold. Resolved once at sweep
// Setup — clusterhealthprobes.healthProbeConfigFromEnv delegates
// the ported-check knobs here and keeps only the sweep-level
// timeouts itself.
package ported

import (
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// ConfigFromEnv fills the ported-check knobs of c — c.DNS,
// c.HTTPContent, c.Pods and c.Quota — from the HEALTH_* env vars.
// The live manifests are the ground truth for the defaults (e.g.
// http-content-check TARGET_URL is the prometheus /-/healthy
// endpoint, not alertmanager).
func ConfigFromEnv(c *probefw.Config) {
	// Second hostname is a ClusterIP Service (DNS record exists
	// regardless of backend pod readiness) — a headless service like
	// alertmanager-operated NXDOMAINs whenever its single pod is
	// recreating, which would flap the DNS check during every
	// alertmanager rollout despite CoreDNS being fine.
	hosts := strings.Split(envx.Getenv("HEALTH_DNS_HOSTNAMES",
		"kubernetes.default.svc.cluster.local,"+
			"kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local"), ",")
	trimmed := hosts[:0]
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			trimmed = append(trimmed, h)
		}
	}
	c.DNS = probefw.DNSConfig{Hostnames: trimmed}
	c.HTTPContent = probefw.HTTPContentConfig{
		URL:      envx.Getenv("HEALTH_HTTP_CONTENT_URL", "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"),
		Expected: envx.Getenv("HEALTH_HTTP_EXPECTED_CONTENT", "Healthy"),
	}
	c.Pods = probefw.PodsConfig{
		Namespace:    envx.Getenv("HEALTH_POD_CHECK_NAMESPACE", "kube-system"),
		MaxRestarts:  int32(envx.GetenvIntMin("HEALTH_MAX_POD_RESTARTS", 10, 0)),
		SkipDuration: envx.GetenvDuration("HEALTH_POD_SKIP_DURATION", 10*time.Minute),
	}
	c.Quota = probefw.QuotaConfig{
		Threshold: envx.GetenvFloatPositive("HEALTH_RESOURCE_QUOTA_THRESHOLD", 0.9),
	}
}
