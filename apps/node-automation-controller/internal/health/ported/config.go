// config.go — the HEALTH_* env resolution for the ported
// kuberhealthy checks: the dns-status-internal hostnames, the
// http-content-check target URL and expected body, the
// pod-restarts/pod-status namespace, restart ceiling and skip
// window, and the resource-quota threshold — one resolver per
// probefw.Config field, matching the per-domain pattern. Resolved
// once at sweep Setup —
// clusterhealthprobes.healthProbeConfigFromEnv assigns each
// returned sub-struct and keeps only the sweep-level timeouts
// itself.
package ported

import (
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// DNSConfigFromEnv resolves cfg.DNS — the HEALTH_DNS_HOSTNAMES csv —
// as the sub-struct the caller assigns.
func DNSConfigFromEnv() probefw.DNSConfig {
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
	return probefw.DNSConfig{Hostnames: trimmed}
}

// HTTPContentConfigFromEnv resolves cfg.HTTPContent — the
// http-content-check target URL and expected body substring — as the
// sub-struct the caller assigns. The live manifest is the ground
// truth for the defaults: TARGET_URL is the prometheus /-/healthy
// endpoint, not alertmanager.
func HTTPContentConfigFromEnv() probefw.HTTPContentConfig {
	return probefw.HTTPContentConfig{
		URL:      envx.Getenv("HEALTH_HTTP_CONTENT_URL", "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"),
		Expected: envx.Getenv("HEALTH_HTTP_EXPECTED_CONTENT", "Healthy"),
	}
}

// PodsConfigFromEnv resolves cfg.Pods — the pod-restarts/pod-status
// census namespace, restart ceiling and young-pod skip window — as
// the sub-struct the caller assigns.
func PodsConfigFromEnv() probefw.PodsConfig {
	return probefw.PodsConfig{
		Namespace:    envx.Getenv("HEALTH_POD_CHECK_NAMESPACE", "kube-system"),
		MaxRestarts:  int32(envx.GetenvIntMin("HEALTH_MAX_POD_RESTARTS", 10, 0)),
		SkipDuration: envx.GetenvDuration("HEALTH_POD_SKIP_DURATION", 10*time.Minute),
	}
}

// QuotaConfigFromEnv resolves cfg.Quota — the resource-quota-check
// used/hard ceiling — as the sub-struct the caller assigns.
func QuotaConfigFromEnv() probefw.QuotaConfig {
	return probefw.QuotaConfig{
		Threshold: envx.GetenvFloatPositive("HEALTH_RESOURCE_QUOTA_THRESHOLD", 0.9),
	}
}
