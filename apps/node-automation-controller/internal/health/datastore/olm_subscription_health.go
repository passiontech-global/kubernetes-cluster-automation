// olm_subscription_health.go — the W7-C5 olm-subscription-health
// check: the OLM CSV / webhook-cert / subscription guard plus the
// olm-operator auto-heal.
package datastore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// olmHealthCheck is the W7-C5 OLM CSV / webhook cert / subscription
// guard plus the olm-operator auto-heal.
type olmHealthCheck struct {
	*probefw.Deps

	// W7-C5 watchdog state (serial sweep — unguarded):
	//   - olmFirstSeen: "kind/ns/name/reason" → first sweep the
	//     unhealthy signature showed; it must persist
	//     olmUnhealthyMinAge before the gauge fires (>= olmHealMinAge
	//     for the CSV-triggered operator heal). Pruned on resolve.
	//   - olmEmitted: the emitted-gauge ledger for the same keys
	//     held at gauge=1 — a tuple not re-seen gets
	//     DeleteLabelValues, not a stale 1.
	//   - olmHealed: reason → last olm-operator pod delete — the 1h
	//     cooldown (in-RAM: deleting the operator pod is the heal,
	//     nothing else can carry the stamp).
	olmFirstSeen state.FirstSeenLedger
	olmEmitted   state.GaugeLedger[string]
	olmHealed    state.CooldownSet
}

// newOlmHealthCheck builds the W7-C5 check — the ledgers arm
// lazily on first use (the GaugeLedger zero value is ready).
func NewOlmHealthCheck(d *probefw.Deps) probefw.Check {
	return &olmHealthCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// olm-subscription-health (W7-C5) — OLM CSV / webhook cert /
// subscription guard + olm-operator auto-heal.
// ---------------------------------------------------------------------------

// W7-C5 — olm-subscription-health knobs.
const (
	// CheckNameOLMHealth is the check's kuberhealthy_check label
	// value — W7; not a ported HealthCheck but reports under its
	// own check name so the generic FAIL alerting path covers it.
	CheckNameOLMHealth = "olm-subscription-health"
	// olmUnhealthyMinAge: an unhealthy CSV/Subscription signature
	// must persist this long before the gauge fires — CSVs
	// legitimately sit in Installing/Replacing during upgrades.
	olmUnhealthyMinAge = 15 * time.Minute
	// olmHealMinAge: a CSV stuck or overdue on webhook cert
	// rotation this long triggers the olm-operator pod delete.
	olmHealMinAge   = 20 * time.Minute
	olmHealCooldown = time.Hour
	// olmOperatorNS/PodPrefix locate the operator pods the heal
	// deletes to force CSV/webhook-cert reconciliation.
	olmOperatorNS        = "olm"
	olmOperatorPodPrefix = "olm-operator"
	// OLM kind label values for the gauge.
	olmKindCSV          = "ClusterServiceVersion"
	olmKindSubscription = "Subscription"
	// Unhealthy-reason gauge label values.
	olmReasonCSVStuck         = "csv_not_succeeded"
	olmReasonCertOverdue      = "cert_rotation_overdue"
	olmReasonCatalogUnhealthy = "catalog_sources_unhealthy"
	olmReasonResolutionFailed = "resolution_failed"
)

// OLM GVRs — dynamic-client reads, skipped gracefully when the CRDs
// are not installed on a cluster.
var (
	olmCSVGVR = kube.GVROLMClusterServiceVersion
	olmSubGVR = kube.GVROLMSubscription
)

var (
	// W7-C5 — the OLM-unhealthy signal: 1 while the CSV/Subscription
	// reports an unhealthy phase/condition past the audit threshold.
	// kind is ClusterServiceVersion | Subscription.
	olmUnhealthyResourcesGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_olm_unhealthy_resources",
		Help: "1 while the OLM resource reports an unhealthy phase/condition past the audit threshold.",
	}, []string{"kind", "namespace", "name", "reason"})

	// W7-C5 — olm-operator pods deleted to unstick wedged CSV/cert-
	// rotation reconciliation, by detected reason. Counts delivered
	// heals only.
	olmOperatorHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_olm_operator_heals_total",
		Help: "olm-operator pods deleted to unstick wedged CSV/cert-rotation reconciliation, by detected reason.",
	}, []string{"reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		olmUnhealthyResourcesGauge,
		olmOperatorHealsTotal)
}

// checkOLMHealth audits the OLM control plane's two user-visible
// surfaces — ClusterServiceVersions and Subscriptions. Unlike
// cert-manager operators, OLM manages and rotates its operands'
// webhook TLS itself via the CSV, so a wedged olm-operator silently
// expires every admission webhook it owns (the NHC/SNR paralysis
// scenario: the remediation operator's webhook dies exactly when a
// node needs fencing):
//
//   - CSV status.phase != "Succeeded" — an install wedged mid-flight;
//   - CSV status.certsRotateAt in the past — the webhook cert
//     rotation OLM owes the operand never landed;
//   - Subscription conditions CatalogSourcesUnhealthy=True /
//     ResolutionFailed=True — a subscription that can no longer
//     resolve its package.
//
// A signature must persist olmUnhealthyMinAge before
// olm_unhealthy_resources=1 fires; a CSV stuck or cert-overdue past
// olmHealMinAge additionally deletes the olm-operator pod (outside
// maintenance, 1h cooldown) to force the missed reconciliation.
func (p *olmHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	// The CR scans and the maintenance mutex both need dyn — a
	// missing client is a wiring bug, not "no signal".
	if r := p.RequireDyn("olm health check"); r != nil {
		return *r
	}
	now := p.Now()

	// The CSV and Subscription scans — a list-level infra failure
	// (other than "OLM not installed") is a run-level Infra verdict.
	scan, lerr := p.collectOLMSignatures(ctx, now)
	if lerr != nil {
		return probefw.Result{Infra: lerr}
	}

	var rep probefw.SweepReport
	healReasons := p.evaluateOLMUnhealthy(ctx, log, scan, now, &rep)
	p.clearOLMResolvedStamps(ctx, log, scan)
	rep.Close(&p.olmEmitted, olmUnhealthyResourcesGauge.DeleteLabelValues)

	if len(healReasons) > 0 {
		reasons := make([]string, 0, len(healReasons))
		for r := range healReasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		p.healOLMOperator(ctx, log, reasons, now)
	}

	return rep.Verdict(fmt.Sprintf(
		"olm resources unhealthy >=%s: ", olmUnhealthyMinAge), ", ")
}

// healOLMOperator deletes the olm-operator pod(s) — a wedged
// operator stops reconciling CSVs and stops rotating the webhook
// certificates it owns, so a restart forces both queues to re-list.
// probefw.BounceOperatorPod carries the gates (the 1h in-RAM
// cooldown — the pod is the heal target, nothing else can carry the
// stamp — and the maintenance mutex, fail closed) plus the
// ns-scoped prefix-filtered list, the UID-preconditioned deletes and
// the census invalidate; the per-reason heal counters key on the
// delivered-delete count.
func (p *olmHealthCheck) healOLMOperator(ctx context.Context,
	log logr.Logger, reasons []string, now time.Time) {

	deleted := p.BounceOperatorPod(ctx, log, olmOperatorPodPrefix,
		olmOperatorNS,
		func(pods []corev1.Pod) []*corev1.Pod {
			var targets []*corev1.Pod
			for i := range pods {
				if strings.HasPrefix(pods[i].Name, olmOperatorPodPrefix) {
					targets = append(targets, &pods[i])
				}
			}
			return targets
		},
		&p.olmHealed, olmOperatorPodPrefix, olmHealCooldown, now)
	if deleted == 0 {
		return
	}
	for _, r := range reasons {
		olmOperatorHealsTotal.WithLabelValues(r).Inc()
	}
}
