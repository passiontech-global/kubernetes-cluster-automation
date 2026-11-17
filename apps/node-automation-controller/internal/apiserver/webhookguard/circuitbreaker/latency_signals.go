// latency_signals.go — Prometheus-backed admission webhook slow/5xx
// signal detection for #2a: queries error rate (calling_webhook_error |
// apiserver_internal_error, excluding no_error) and p99 admission
// duration per sub-webhook name. Continuous breaches >=10m emit
// node_automation_webhook_admission_degraded and trigger a stage-1
// backing-pod bounce; >=15m trips failurePolicy to Ignore (unless
// AnnoWebhookNeverFailOpen=="true") and gates recovery until both
// endpoints and metrics are clean for RecoverConfirmSweeps.
package circuitbreaker

import (
	"context"
	"strings"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// DegradedThreshold is how long a fail-closed sub-webhook must
	// continuously breach error-rate or p99 latency before emitting
	// WebhookAdmissionDegraded and bouncing its oldest Ready pod.
	DegradedThreshold = 10 * time.Minute

	// LatencyTripThreshold is how long a degraded sub-webhook must
	// persist before tripping failurePolicy to Ignore (when enabled
	// and not opted out via AnnoWebhookNeverFailOpen).
	LatencyTripThreshold = 15 * time.Minute

	defaultErrorRateThreshold = 0.5
	defaultLatencyP99Seconds  = 5.0

	reasonErrorRate  = "error_rate"
	reasonLatencyP99 = "latency_p99"

	// promErrorRateQuery measures 5xx / webhook-call failure ratio per
	// admission webhook name, strictly excluding error_type="no_error".
	promErrorRateQuery = `sum by (name) (rate(apiserver_admission_webhook_rejection_count{error_type=~"calling_webhook_error|apiserver_internal_error"}[5m])) / clamp_min(sum by (name) (rate(apiserver_admission_webhook_admission_duration_seconds_count[5m])), 0.001)`

	// promLatencyP99Query measures p99 admission webhook duration per name.
	promLatencyP99Query = `histogram_quantile(0.99, sum by (name, le) (rate(apiserver_admission_webhook_admission_duration_seconds_bucket[5m])))`
)

type latencyKey struct {
	kind, cfg, webhook, reason string
}

type latencySignals struct {
	breaches   map[string]string // sub-webhook name -> reason ("error_rate"|"latency_p99")
	queryError bool
}

func (b *Breaker) effDegradedThreshold() time.Duration {
	if b.degradedThreshold > 0 {
		return b.degradedThreshold
	}
	return DegradedThreshold
}

func (b *Breaker) effLatencyTripThreshold() time.Duration {
	if b.latencyTripThreshold > 0 {
		return b.latencyTripThreshold
	}
	return LatencyTripThreshold
}

func (b *Breaker) queryLatencySignals(ctx context.Context, g *guardstate.Guard) latencySignals {
	if g == nil || g.PromEndpoint == "" {
		return latencySignals{}
	}
	errThresh := g.WebhookErrorRateThreshold
	if errThresh <= 0 {
		errThresh = defaultErrorRateThreshold
	}
	latThresh := g.WebhookLatencyP99Seconds
	if latThresh <= 0 {
		latThresh = defaultLatencyP99Seconds
	}
	log := logf.FromContext(ctx)
	breaches := map[string]string{}

	errSamples, err := g.PromClient.InstantQuery(ctx, g.PromEndpoint, promErrorRateQuery)
	if err != nil {
		metrics.IncError(g.Queue)
		log.Error(err, "webhook error-rate prometheus query failed")
		return latencySignals{queryError: true}
	}
	for _, s := range errSamples {
		if s.Metric["error_type"] == "no_error" {
			continue
		}
		name := s.Label("name", "webhook")
		if name != "" && s.Value >= errThresh {
			breaches[name] = reasonErrorRate
		}
	}

	latSamples, err := g.PromClient.InstantQuery(ctx, g.PromEndpoint, promLatencyP99Query)
	if err != nil {
		metrics.IncError(g.Queue)
		log.Error(err, "webhook p99 latency prometheus query failed")
		return latencySignals{queryError: true}
	}
	for _, s := range latSamples {
		name := s.Label("name", "webhook")
		if name != "" && s.Value >= latThresh {
			if _, already := breaches[name]; !already {
				breaches[name] = reasonLatencyP99
			}
		}
	}
	return latencySignals{breaches: breaches}
}

// latencyVerdict summarizes metric-driven degradation decisions for a single
// webhook configuration sweep.
type latencyVerdict struct {
	holdForMetrics map[string]bool   // sub-webhook names blocked from Ignore->Fail recover
	tripForMetrics map[string]string // sub-webhook names >=15m eligible to trip -> reason
	bounceServices []string          // backend ns/name services >=10m to bounce
}

func (s *circuitSweep) evaluateLatency(cfg guardstate.WebhookConfigView) latencyVerdict {
	var out latencyVerdict
	neverFailOpen := cfg.Annotations[kube.AnnoWebhookNeverFailOpen] == "true"
	broken := guardstate.ParseCircuitAnnotation(cfg.Anno)
	degradedWindow := s.b.effDegradedThreshold()
	tripWindow := s.b.effLatencyTripThreshold()

	for _, h := range cfg.Hooks {
		key := cfg.Kind + "/" + cfg.Name + "/" + h.Name
		if s.latency.queryError {
			// When Prometheus cannot be queried, preserve any already-emitted
			// metric-degraded sub-webhook so a broken entry does not prematurely recover.
			for lk := range s.b.degradedEmitted.Last() {
				if lk.kind == cfg.Kind && lk.cfg == cfg.Name && lk.webhook == h.Name {
					if out.holdForMetrics == nil {
						out.holdForMetrics = map[string]bool{}
					}
					out.holdForMetrics[h.Name] = true
					break
				}
			}
			continue
		}

		reason := s.latency.breaches[h.Name]
		if reason == "" {
			continue
		}
		if !guardstate.FailClosed(h.FailurePolicy) && !broken[h.Name] {
			continue
		}
		s.latencySeen[key] = true
		first, tracked := s.b.degradedSince.Observe(key, s.now)
		if !tracked {
			continue
		}
		elapsed := s.now.Sub(first)
		if elapsed < degradedWindow {
			continue
		}
		lk := latencyKey{kind: cfg.Kind, cfg: cfg.Name, webhook: h.Name, reason: reason}
		s.b.degradedEmitted.Set(metrics.WebhookAdmissionDegraded, 1, lk,
			cfg.Kind, cfg.Name, h.Name, reason)
		if out.holdForMetrics == nil {
			out.holdForMetrics = map[string]bool{}
		}
		out.holdForMetrics[h.Name] = true

		if s.allowTrips && h.Service != nil && h.Service.Namespace != "" && h.Service.Name != "" {
			out.bounceServices = append(out.bounceServices, h.Service.Namespace+"/"+h.Service.Name)
		}
		if s.allowTrips && elapsed >= tripWindow && !broken[h.Name] &&
			s.g.LatencyBreakerTripEnabled && !neverFailOpen {
			if out.tripForMetrics == nil {
				out.tripForMetrics = map[string]string{}
			}
			out.tripForMetrics[h.Name] = reason
		}
	}
	return out
}

func (b *Breaker) carryDegradedForward() {
	for k, lv := range b.degradedEmitted.Last() {
		b.degradedEmitted.Emit(k, lv...)
	}
}

func appendUniqueServices(dst []string, seen map[string]bool, src []string) []string {
	for _, svc := range src {
		if !seen[svc] {
			seen[svc] = true
			dst = append(dst, svc)
		}
	}
	return dst
}

func joinReason(r string) string {
	return strings.ReplaceAll(r, "_", "-")
}
