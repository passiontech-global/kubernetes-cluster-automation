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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// DNSConfig — dns-status-internal: every hostname must resolve.
type DNSConfig struct {
	Hostnames []string // HEALTH_DNS_HOSTNAMES
}

// PodsConfig — pod-restarts and pod-status checks.
type PodsConfig struct {
	Namespace    string        // HEALTH_POD_CHECK_NAMESPACE
	MaxRestarts  int32         // HEALTH_MAX_POD_RESTARTS
	SkipDuration time.Duration // HEALTH_POD_SKIP_DURATION
}

// QuotaConfig — resource-quota-check: the used/hard ceiling.
type QuotaConfig struct {
	Threshold float64 // HEALTH_RESOURCE_QUOTA_THRESHOLD
}

// DNSConfigFromEnv resolves HEALTH_DNS_HOSTNAMES.
func DNSConfigFromEnv() DNSConfig {
	var trimmed []string
	for h := range strings.SplitSeq(envx.Getenv("HEALTH_DNS_HOSTNAMES",
		"kubernetes.default.svc.cluster.local,"+
			"kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			trimmed = append(trimmed, h)
		}
	}
	return DNSConfig{Hostnames: trimmed}
}

// HTTPContentConfigFromEnv resolves HEALTH_HTTP_CONTENT_URL and
// HEALTH_HTTP_EXPECTED_CONTENT.
func HTTPContentConfigFromEnv() probefw.HTTPContentConfig {
	return probefw.HTTPContentConfig{
		URL:      envx.Getenv("HEALTH_HTTP_CONTENT_URL", "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"),
		Expected: envx.Getenv("HEALTH_HTTP_EXPECTED_CONTENT", "Healthy"),
	}
}

// PodsConfigFromEnv resolves pod-restarts/pod-status knobs.
func PodsConfigFromEnv() PodsConfig {
	return PodsConfig{
		Namespace:    envx.Getenv("HEALTH_POD_CHECK_NAMESPACE", "kube-system"),
		MaxRestarts:  int32(envx.GetenvIntMin("HEALTH_MAX_POD_RESTARTS", 10, 0)),
		SkipDuration: envx.GetenvDuration("HEALTH_POD_SKIP_DURATION", 10*time.Minute),
	}
}

// QuotaConfigFromEnv resolves resource-quota-check's threshold.
func QuotaConfigFromEnv() QuotaConfig {
	return QuotaConfig{
		Threshold: envx.GetenvFloatPositive("HEALTH_RESOURCE_QUOTA_THRESHOLD", 0.9),
	}
}
