// apiserver_admission_token_guard.go — health check "apiserver-admission-token-guard":
// detect-only PromQL guard identifying control-plane admission and token pressure:
//  1. Admission webhook p99 latency > 2s sustained >= 10m
//     (apiserver_admission_webhook_admission_duration_seconds_bucket), naming the webhook.
//  2. Cluster-wide TokenRequest (subresource="token") burst (> 10 req/s) or
//     sustained APF rejections (apiserver_flowcontrol_rejected_requests_total > 0)
//     sustained >= 10m, naming the client or flow_schema.
//
// Gracefully skips/passes when Prometheus is unavailable.
// Emits node_automation_apiserver_admission_token_anomaly{kind,target} and
// cooldown-deduped Warning Events (APIServerAdmissionTokenAnomaly).
package watchdogs

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameAPIServerAdmissionTokenGuard is the registry check name for apiserver-admission-token-guard.
	CheckNameAPIServerAdmissionTokenGuard = "apiserver-admission-token-guard"

	admissionTokenMinAge         = 10 * time.Minute
	admissionTokenEventCooldown  = 30 * time.Minute
	admissionTokenMaxEventsSweep = 20
	admissionTokenEventReason    = "APIServerAdmissionTokenAnomaly"
	admissionTokenEventNamespace = "kube-system"

	admissionWebhookLatencyThreshold = 2.0  // seconds (p99)
	tokenRequestBurstThreshold       = 10.0 // requests/sec

	anomalyKindWebhookLatency = "webhook_latency"
	anomalyKindTokenBurst     = "token_request_burst"
	anomalyKindAPFRejected    = "apf_rejected_requests"

	admissionWebhookP99Query = `histogram_quantile(0.99, sum by (le, name, type) (rate(apiserver_admission_webhook_admission_duration_seconds_bucket[5m]))) > 2`
	tokenRequestBurstQuery   = `topk(5, sum by (client) (rate(apiserver_request_total{resource="serviceaccounts",subresource="token"}[5m]))) > 10`
	apfRejectedQuery         = `sum by (flow_schema, priority_level) (rate(apiserver_flowcontrol_rejected_requests_total[5m])) > 0`
)

var apiserverAdmissionTokenAnomalyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_apiserver_admission_token_anomaly",
	Help: "1 while an admission webhook p99 latency >2s, TokenRequest burst, or APF rejection anomaly persists >=10m.",
}, []string{"kind", "target"})

func init() {
	ctrlmetrics.Registry.MustRegister(apiserverAdmissionTokenAnomalyGauge)
}

type apiserverAdmissionTokenGuardCheck struct {
	*probefw.Deps

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewAPIServerAdmissionTokenGuardCheck constructs the apiserver-admission-token-guard check.
func NewAPIServerAdmissionTokenGuardCheck(d *probefw.Deps) probefw.Check {
	return &apiserverAdmissionTokenGuardCheck{Deps: d}
}

type admissionTokenFinding struct {
	kind   string
	target string
	value  float64
}

func (c *apiserverAdmissionTokenGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, admissionTokenEventCooldown)

	if _, err := c.PromEndpointCtx(ctx); err != nil {
		log.V(1).Info("apiserver-admission-token-guard skipped: prometheus endpoint unavailable", "error", err)
		return c.carryForwardResult()
	}

	webhookSamples, werr := c.PromQuery(ctx, admissionWebhookP99Query)
	if werr != nil {
		log.V(1).Info("apiserver-admission-token-guard skipped: webhook latency query unavailable", "error", werr)
		return c.carryForwardResult()
	}
	tokenSamples, terr := c.PromQuery(ctx, tokenRequestBurstQuery)
	if terr != nil {
		log.V(1).Info("apiserver-admission-token-guard skipped: token request query unavailable", "error", terr)
		return c.carryForwardResult()
	}
	apfSamples, aerr := c.PromQuery(ctx, apfRejectedQuery)
	if aerr != nil {
		log.V(1).Info("apiserver-admission-token-guard skipped: apf rejected query unavailable", "error", aerr)
		return c.carryForwardResult()
	}

	var raw []admissionTokenFinding
	seenRaw := map[string]bool{}
	addRaw := func(kind, target string, val float64) {
		k := kind + "/" + target
		if seenRaw[k] {
			return
		}
		seenRaw[k] = true
		raw = append(raw, admissionTokenFinding{kind: kind, target: target, value: val})
	}

	for _, s := range webhookSamples {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value <= admissionWebhookLatencyThreshold {
			continue
		}
		name := cmp.Or(s.Label("name", "webhook", "target"), "unknown")
		if wtype := s.Label("type"); wtype != "" {
			name = wtype + "/" + name
		}
		addRaw(anomalyKindWebhookLatency, name, s.Value)
	}
	for _, s := range tokenSamples {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value <= tokenRequestBurstThreshold {
			continue
		}
		target := cmp.Or(s.Label("client", "user"), "cluster")
		addRaw(anomalyKindTokenBurst, target, s.Value)
	}
	for _, s := range apfSamples {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value <= 0 {
			continue
		}
		target := cmp.Or(s.Label("flow_schema", "priority_level"), "cluster")
		addRaw(anomalyKindAPFRejected, target, s.Value)
	}

	var rep probefw.SweepReport
	var findings []admissionTokenFinding
	liveFirstSeen := map[string]bool{}

	for _, f := range raw {
		key := f.kind + "/" + f.target
		liveFirstSeen[key] = true
		if !probefw.Persisted(&c.firstSeen, key, now, admissionTokenMinAge, log) {
			continue
		}
		rep.Emit(apiserverAdmissionTokenAnomalyGauge, key,
			[]string{f.kind, f.target},
			fmt.Sprintf("%s:%s (%.2f)", f.kind, f.target, f.value))
		findings = append(findings, f)
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	slices.SortFunc(findings, func(a, b admissionTokenFinding) int {
		if x := cmp.Compare(a.kind, b.kind); x != 0 {
			return x
		}
		return cmp.Compare(a.target, b.target)
	})

	c.emitEvents(ctx, log, now, findings)

	return rep.Result(&c.emitted, apiserverAdmissionTokenAnomalyGauge.DeleteLabelValues,
		"apiserver admission/token anomaly: ", ", ")
}

func (c *apiserverAdmissionTokenGuardCheck) carryForwardResult() probefw.Result {
	var rep probefw.SweepReport
	for k, lv := range c.emitted.Last() {
		rep.Carry(k, lv)
	}
	return rep.Result(&c.emitted, apiserverAdmissionTokenAnomalyGauge.DeleteLabelValues,
		"apiserver admission/token anomaly: ", ", ")
}

func (c *apiserverAdmissionTokenGuardCheck) emitEvents(ctx context.Context, log logr.Logger, now time.Time, findings []admissionTokenFinding) {
	emitted := 0
	for _, f := range findings {
		if emitted >= admissionTokenMaxEventsSweep {
			log.Info("SKIP rest: apiserver-admission-token-guard event cap reached",
				"cap", admissionTokenMaxEventsSweep)
			break
		}
		cooldownKey := "apitoken." + f.kind + "." + f.target
		note := fmt.Sprintf("API server %s anomaly on %q sustained >=%s (value=%.2f)",
			f.kind, f.target, admissionTokenMinAge, f.value)
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, admissionTokenEventCooldown, now, kube.WarningEvent{
			Namespace: admissionTokenEventNamespace,
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Namespace",
				Name:       admissionTokenEventNamespace,
			},
			Reason:            admissionTokenEventReason,
			Note:              note,
			ReportingInstance: cmp.Or(c.Name, CheckNameAPIServerAdmissionTokenGuard),
		}) {
			emitted++
		}
	}
}
