package datastore

import (
	"context"
	"errors"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
	//   - olmEmitted: same keys held at gauge=1 — a tuple not
	//     re-seen gets DeleteLabelValues, not a stale 1.
	//   - olmHealed: reason → last olm-operator pod delete — the 1h
	//     cooldown (in-RAM: deleting the operator pod is the heal,
	//     nothing else can carry the stamp).
	olmFirstSeen state.FirstSeenLedger
	olmEmitted   map[string]bool
	olmHealed    state.CooldownSet
}

// newOlmHealthCheck builds the W7-C5 check — the ledgers arm
// lazily on first use; only the emitted-series map needs the
// explicit initialization that used to live in the monolithic
// newClusterHealthProber literal.
func NewOlmHealthCheck(d *probefw.Deps) probefw.Check {
	return &olmHealthCheck{Deps: d,
		olmEmitted: map[string]bool{},
	}
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
	if p.Dyn == nil {
		return probefw.Result{Infra: errors.New(
			"no dynamic client — olm health check unverifiable")}
	}
	now := p.Now()
	if p.olmEmitted == nil {
		p.olmEmitted = map[string]bool{}
	}

	// live signatures keyed "kind/ns/name/reason".
	live := map[string]bool{}
	csvs, err := p.Dyn.Resource(olmCSVGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// OLM not installed on this cluster — nothing to audit.
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list clusterserviceversions: %w", err)}
	default:
		for i := range csvs.Items {
			csv := &csvs.Items[i]
			obj := olmKindCSV + "/" + csv.GetNamespace() + "/" + csv.GetName()
			phase, _ := kube.NestedString(csv.Object, "status", "phase")
			if phase != "Succeeded" {
				live[obj+"/"+olmReasonCSVStuck] = true
			}
			if ts, found := kube.NestedString(
				csv.Object, "status", "certsRotateAt"); found && ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil && now.After(t) {
					live[obj+"/"+olmReasonCertOverdue] = true
				}
			}
		}
	}
	subs, err := p.Dyn.Resource(olmSubGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list subscriptions: %w", err)}
	default:
		for i := range subs.Items {
			sub := &subs.Items[i]
			obj := olmKindSubscription + "/" +
				sub.GetNamespace() + "/" + sub.GetName()
			for _, c := range kube.Conditions(sub.Object, "status", "conditions") {
				if c.Status != "True" {
					continue
				}
				switch c.Type {
				case "CatalogSourcesUnhealthy":
					live[obj+"/"+olmReasonCatalogUnhealthy] = true
				case "ResolutionFailed":
					live[obj+"/"+olmReasonResolutionFailed] = true
				}
			}
		}
	}

	emitted := map[string]bool{}     // keys past the gauge window
	healReasons := map[string]bool{} // reasons past the heal window (CSV only)
	p.olmFirstSeen.Prune(func(k string) bool { return live[k] })
	for k := range live {
		first, tracked := p.olmFirstSeen.Observe(k, now)
		if !tracked {
			log.Info("olm unhealthy signature — tracking first-seen",
				"signature", k)
			continue
		}
		if now.Sub(first) < olmUnhealthyMinAge {
			continue
		}
		emitted[k] = true
		parts := strings.SplitN(k, "/", 4)
		metrics.OLMUnhealthyResources.
			WithLabelValues(parts[0], parts[1], parts[2], parts[3]).Set(1)
		// The heal is CSV-scoped: a subscription failure is the
		// catalog's problem, not olm-operator's queue.
		if parts[0] == olmKindCSV && now.Sub(first) >= olmHealMinAge {
			healReasons[parts[3]] = true
		}
	}
	for k := range p.olmEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 4); len(parts) == 4 {
			metrics.OLMUnhealthyResources.DeleteLabelValues(
				parts[0], parts[1], parts[2], parts[3])
		}
		delete(p.olmEmitted, k)
	}
	maps.Copy(p.olmEmitted, emitted)

	if len(healReasons) > 0 {
		reasons := make([]string, 0, len(healReasons))
		for r := range healReasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		p.healOLMOperator(ctx, log, reasons, now)
	}

	if len(emitted) == 0 {
		return probefw.Result{Pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probefw.Result{Why: fmt.Sprintf(
		"olm resources unhealthy >=%s: %s",
		olmUnhealthyMinAge, strings.Join(keys, ", "))}
}

// healOLMOperator deletes the olm-operator pod(s) — a wedged
// operator stops reconciling CSVs and stops rotating the webhook
// certificates it owns, so a restart forces both queues to re-list.
// Gates: the 1h in-RAM cooldown (the pod is the heal target —
// nothing else can carry the stamp) and the maintenance mutex, same
// shape as every pod-delete heal in this sweep.
func (p *olmHealthCheck) healOLMOperator(ctx context.Context,
	log logr.Logger, reasons []string, now time.Time) {

	if p.olmHealed.CooledDown(olmOperatorPodPrefix, olmHealCooldown, now) {
		log.Info("skip heal: olm-operator inside cooldown")
		return
	}
	held, why, err := kube.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "why", why)
		return
	}
	pods, err := p.CS.CoreV1().Pods(olmOperatorNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list olm-operator pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, olmOperatorPodPrefix) {
			continue
		}
		uid := pod.UID
		if err := p.CS.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "olm-operator delete failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		deleted = true
		log.Info("DELETE: wedged olm-operator — stuck CSV/cert-rotation queues need a resync",
			"pod", pod.Namespace+"/"+pod.Name,
			"reasons", strings.Join(reasons, ","))
	}
	if !deleted {
		return
	}
	p.olmHealed.Stamp(olmOperatorPodPrefix, now)
	for _, r := range reasons {
		metrics.OLMOperatorHealsTotal.WithLabelValues(r).Inc()
	}
}
