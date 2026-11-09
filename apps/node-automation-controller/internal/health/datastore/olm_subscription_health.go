// olm_subscription_health.go — the olm-subscription-health olm-subscription-health
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// olmHealthCheck is the olm-subscription-health OLM CSV / webhook cert / subscription
// guard plus the olm-operator auto-heal.
type olmHealthCheck struct {
	*probefw.Deps

	// olm-subscription-health watchdog state (serial sweep — unguarded):
	//   - olmFirstSeen: "kind/ns/name/reason" → first sweep the
	//     unhealthy signature showed; it must persist
	//     olmUnhealthyMinAge before the gauge fires (>= olmHealMinAge
	//     for the CSV-triggered operator heal). Pruned on resolve.
	//   - olmEmitted: the emitted-gauge ledger for the same keys
	//     held at gauge=1 — a tuple not re-seen gets
	//     DeleteLabelValues, not a stale 1.
	//   - olmHealed: controller key (kube.PodControllerKey) → last
	//     olm-operator pod delete — the in-RAM half of the 1h
	//     cooldown (the passiontech.dev/last-olm-operator-heal stamp
	//     on the olm-operator Deployment is the durable half).
	olmFirstSeen state.FirstSeenLedger
	olmEmitted   state.GaugeLedger[string]
	olmHealed    state.CooldownSet
}

// newOlmHealthCheck builds the olm-subscription-health check — the ledgers arm
// lazily on first use (the GaugeLedger zero value is ready).
func NewOlmHealthCheck(d *probefw.Deps) probefw.Check {
	return &olmHealthCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// olm-subscription-health (olm-subscription-health) — OLM CSV / webhook cert /
// subscription guard + olm-operator auto-heal.
// ---------------------------------------------------------------------------

// olm-subscription-health — olm-subscription-health knobs.
const (
	// CheckNameOLMHealth is the check's kuberhealthy_check label
	// value — agent-added; not a ported HealthCheck but reports under its
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
	// olmHealAnno persists the last olm-operator heal moment on the
	// operator's Deployment — the restart-proof half of the cooldown.
	olmHealAnno = kube.AnnoLastOLMOperatorHeal
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
	// olm-subscription-health — the OLM-unhealthy signal: 1 while the CSV/Subscription
	// reports an unhealthy phase/condition past the audit threshold.
	// kind is ClusterServiceVersion | Subscription.
	olmUnhealthyResourcesGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_olm_unhealthy_resources",
		Help: "1 while the OLM resource reports an unhealthy phase/condition past the audit threshold.",
	}, []string{"kind", "namespace", "name", "reason"})

	// olm-subscription-health — olm-operator pods deleted to unstick wedged CSV/cert-
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

	// W20-CP3 durable patches — independent of the unhealthy gauge:
	// CSV spec re-assertions (argocd-operator probes, NMO
	// --leader-elect strip) and the everest InstallPlan approver.
	// Tolerated sub-failures: each logs + IncErrors internally.
	p.autoPatchOperatorCSVs(ctx, log)
	p.autoApproveStuckInstallPlans(ctx, log, now)

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

// healOLMOperator deletes at most ONE olm-operator pod per cycle —
// a wedged operator stops reconciling CSVs and stops rotating the
// webhook certificates it owns, so a restart forces both queues to
// re-list; deleting every replica at once would blind the whole
// control plane. The candidate filter requires a controller owner
// (a solo pod has no controller to recreate it — deleting it is
// permanent loss, not a heal), is not already terminating, and the
// cooldown keys on the pod's CONTROLLER (kube.PodControllerKey —
// the ReplicaSet name outlives every pod it spawns) widened by the
// passiontech.dev/last-olm-operator-heal stamp persisted on the
// olm-operator Deployment (survives operator restarts). A
// Deployment read failure defers the heal fail-closed, and an
// absent Deployment collapses the gate to the ledger half.
func (p *olmHealthCheck) healOLMOperator(ctx context.Context,
	log logr.Logger, reasons []string, now time.Time) {

	// The durable cooldown half rides the operator's own Deployment —
	// the one object whose lifetime spans the heal window. A
	// transient read failure defers (fail closed); NotFound means
	// there is nothing to annotate and the gate degrades to the
	// ledger-only shape (AllowedVPersisted's nil-obj contract).
	var obj metav1.Object
	dep, err := p.CS.AppsV1().Deployments(olmOperatorNS).
		Get(ctx, olmOperatorPodPrefix, metav1.GetOptions{})
	switch {
	case err == nil:
		obj = dep
	case apierrors.IsNotFound(err):
	default:
		metrics.IncError(p.Name)
		log.Info("WARN: read olm-operator deployment failed — heal deferred",
			"error", err)
		return
	}

	// Pick ONE candidate from the sweep's pod snapshot before the
	// gate — a terminating or controller-less operator pod is never
	// ours to delete, and with no candidate at all the heal budget
	// and the mutex verdict slot stay unspent.
	pods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — olm-operator heal deferred",
			"error", err)
		return
	}
	var target *corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != olmOperatorNS ||
			!strings.HasPrefix(pod.Name, olmOperatorPodPrefix) ||
			pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			metav1.GetControllerOf(pod) == nil {
			continue
		}
		if target == nil || pod.Name < target.Name {
			target = pod // deterministic pick under the 1-per-cycle cap
		}
	}
	if target == nil {
		return
	}

	// Gate: per-controller cooldown + persisted Deployment stamp +
	// maintenance mutex (memoized on the Deps-wide verdict), fail
	// closed on unverifiable.
	key := kube.PodControllerKey(target)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.olmHealed, obj, olmHealAnno, key, olmHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	if _, err := heal.DeletePod(ctx, p.CS, &p.olmHealed, key, target,
		now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "olm-operator pod delete failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	p.InvalidatePods(ctx) // pod gone — drop the census
	for _, r := range reasons {
		olmOperatorHealsTotal.WithLabelValues(r).Inc()
	}
	log.Info("DELETE: olm-operator pod heal — forcing CSV/cert resync",
		"pod", target.Namespace+"/"+target.Name)
	// Persist the stamp on the Deployment — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half (the delivered
	// delete already stamped olmHealed) holding; nil ledger because
	// the in-RAM key is the per-controller cooldown stamped above.
	if err := heal.StampPersisted(ctx,
		func(ctx context.Context, data []byte) error {
			_, err := p.CS.AppsV1().Deployments(olmOperatorNS).
				Patch(ctx, olmOperatorPodPrefix, types.MergePatchType, data,
					metav1.PatchOptions{})
			return err
		},
		olmHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist olm-operator heal stamp failed",
			"deployment", olmOperatorNS+"/"+olmOperatorPodPrefix)
	}
}
