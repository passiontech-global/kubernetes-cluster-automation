// api_object_sprawl_report_gc.go — the
// api-object-sprawl-report-gc check: a per-namespace object census of
// the sprawl-prone report CRDs plus helm release secrets, a GC of
// orphaned trivy/policy reports (owner gone + aged out), and a cap on
// superseded helm revision secrets — the Kine/apiserver bloat guard.
package nodehealth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// apiObjectSprawlReportGCCheck is the report-garbage and helm-secret
// bloat watchdog.
type apiObjectSprawlReportGCCheck struct {
	*probefw.Deps

	// emitted* are the emitted-gauge ledgers — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale value (zero value usable; the serial sweep needs no
	// lock).
	emittedObjects state.GaugeLedger[string]
	emittedOrphans state.GaugeLedger[string]
	emittedHelm    state.GaugeLedger[string]
}

// NewAPIObjectSprawlReportGCCheck builds the sprawl-gc check — its
// state is the emitted-gauge ledgers; deletes carry no cooldown
// because the GC is idempotent (the object is simply gone next sweep).
func NewAPIObjectSprawlReportGCCheck(d *probefw.Deps) probefw.Check {
	return &apiObjectSprawlReportGCCheck{Deps: d}
}

const (
	CheckNameAPIObjectSprawlReportGC = "api-object-sprawl-report-gc"

	// api-object-sprawl-report-gc knobs.
	sprawlOrphanMinAge     = 2 * time.Hour
	sprawlMaxOrphanDeletes = 50
	sprawlMaxSuperseded    = 10

	// sprawlHelmSecretType is the Secret type helm writes per
	// revision — same literal helmrelease-unlocker selects on.
	sprawlHelmSecretType = "helm.sh/release.v1"
	// sprawlHelmSecretsResource is the resource label the census
	// reports helm release secrets under (they are core Secrets, so
	// no GVR of their own exists to reuse).
	sprawlHelmSecretsResource = "helm_release_secrets"
)

// sprawlReportKinds is the census + orphan-GC table: the report CRDs
// that pile up per ReplicaSet/Pod churn (trivy operator emits one
// report per workload revision and never GCs the dead-owner ones).
// kind is the gauge label value — the resource string keeps the
// series readable without a singular/plural mapping.
var sprawlReportKinds = []struct {
	gvr      schema.GroupVersionResource
	kind     string
	resource string
}{
	{kube.GVRVulnerabilityReport, "vulnerabilityreport", "vulnerabilityreports"},
	{kube.GVRConfigAuditReport, "configauditreport", "configauditreports"},
	{kube.GVRExposedSecretReport, "exposedsecretreport", "exposedsecretreports"},
	{kube.GVREphemeralReport, "ephemeralreport", "ephemeralreports"},
	{kube.GVRPolicyReport, "policyreport", "policyreports"},
}

var (
	// Per-namespace object count of the sprawl-prone resources.
	apiObjectCountGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_api_object_count",
		Help: "Objects per sprawl-prone resource kind and namespace — the apiserver/Kine bloat census.",
	}, []string{"resource", "namespace"})

	// Reports whose controller owner no longer exists (pending GC).
	ephemeralReportsOrphanedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_ephemeral_reports_orphaned",
		Help: "Report CRs older than the orphan window whose controller owner is gone, by report kind.",
	}, []string{"kind"})

	// Orphaned reports deleted by this check.
	ephemeralReportsDeletedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_ephemeral_reports_deleted_total",
		Help: "Dead-owner report CRs deleted by the sprawl GC, by report kind.",
	}, []string{"kind"})

	// Superseded helm revision secrets above the keep cap, per release.
	helmSecretsExcessGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_helm_release_secrets_excess",
		Help: "Superseded helm release secrets beyond the per-release keep cap.",
	}, []string{"namespace", "release"})

	// Superseded helm revision secrets pruned by this check.
	helmSecretsPrunedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_helm_release_secrets_pruned_total",
		Help: "Superseded helm release secrets pruned by the sprawl GC, by namespace.",
	}, []string{"namespace"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		apiObjectCountGauge,
		ephemeralReportsOrphanedGauge,
		ephemeralReportsDeletedTotal,
		helmSecretsExcessGauge,
		helmSecretsPrunedTotal)
}

// checkAPIObjectSprawlReportGC runs the sprawl sweep: census the
// report CRDs + helm release secrets per namespace, delete up to
// sprawlMaxOrphanDeletes reports per cycle that are older than
// sprawlOrphanMinAge AND whose controller owner (Pod or ReplicaSet —
// the only owner kinds trivy/policy-reporter stamps here) provably no
// longer exists, and cap superseded helm revision secrets at
// sprawlMaxSuperseded per release. The check FAILs while any sprawl
// evidence is live — orphans awaiting GC or releases above the keep
// cap.
func (p *apiObjectSprawlReportGCCheck) Run(ctx context.Context) probefw.Result {
	// The report census needs dyn — a missing client is a wiring
	// bug, not "no signal" (same posture as the scylla check).
	if p.Dyn == nil {
		return probefw.Result{Infra: errors.New(
			"no dynamic client — api object sprawl gc unverifiable")}
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	objectCurrent := map[string][]string{}
	orphanCurrent := map[string][]string{}
	var findings []string
	orphanBudget := sprawlMaxOrphanDeletes
	for _, rk := range sprawlReportKinds {
		items, err := p.Dyn.Resource(rk.gvr).List(ctx, metav1.ListOptions{})
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // report CRD absent on this cluster — no census, no GC
		case err != nil:
			// A failed read makes the sweep partial — bail before any
			// ledger Prune so live series are not dropped on a flap.
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.resource, err)}
		}
		perNS := map[string]int{}
		orphaned := 0
		for i := range items.Items {
			obj := &items.Items[i]
			perNS[obj.GetNamespace()]++
			if now.Sub(obj.GetCreationTimestamp().Time) < sprawlOrphanMinAge {
				continue
			}
			if !p.reportOwnerGone(ctx, obj) {
				continue
			}
			orphaned++
			if orphanBudget <= 0 {
				continue // GC capped this cycle — still counted
			}
			if p.deleteOrphanReport(ctx, log, rk, obj) {
				orphanBudget--
			}
		}
		for ns, count := range perNS {
			lv := []string{rk.resource, ns}
			objectCurrent[rk.resource+"/"+ns] = lv
			apiObjectCountGauge.WithLabelValues(lv...).Set(float64(count))
		}
		lv := []string{rk.kind}
		orphanCurrent[rk.kind] = lv
		ephemeralReportsOrphanedGauge.WithLabelValues(lv...).Set(float64(orphaned))
		if orphaned > 0 {
			findings = append(findings,
				fmt.Sprintf("%d orphaned %s", orphaned, rk.resource))
		}
	}

	helmFindings, helmCurrent, err := p.pruneHelmSecrets(ctx, log, objectCurrent)
	if err != nil {
		return probefw.Result{Infra: err}
	}
	findings = append(findings, helmFindings...)

	p.emittedObjects.Reconcile(objectCurrent, apiObjectCountGauge.DeleteLabelValues)
	p.emittedOrphans.Reconcile(orphanCurrent, ephemeralReportsOrphanedGauge.DeleteLabelValues)
	p.emittedHelm.Reconcile(helmCurrent, helmSecretsExcessGauge.DeleteLabelValues)
	if len(findings) == 0 {
		return probefw.Result{Pass: true}
	}
	sort.Strings(findings)
	return probefw.Result{Why: "api object sprawl: " + strings.Join(findings, ", ")}
}

// reportOwnerGone reports whether the report's controller owner is a
// Pod or ReplicaSet that provably no longer exists — the only owner
// kinds the GC deletes on. Reports with no controller owner, or an
// owner of any other kind (Job, StatefulSet, the report's own
// parent-report), fail closed: not evidence of orphanhood. Lookup
// errors other than NotFound also fail closed.
func (p *apiObjectSprawlReportGCCheck) reportOwnerGone(ctx context.Context,
	obj *unstructured.Unstructured) bool {

	ref := metav1.GetControllerOf(obj)
	if ref == nil {
		return false
	}
	ns := obj.GetNamespace()
	var err error
	switch ref.Kind {
	case "Pod":
		_, err = p.CS.CoreV1().Pods(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	case "ReplicaSet":
		_, err = p.CS.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
	default:
		return false
	}
	return apierrors.IsNotFound(err)
}

// deleteOrphanReport removes one orphaned report with a UID
// precondition — the "delete the object I vetted" shape every reaper
// in this codebase uses.
func (p *apiObjectSprawlReportGCCheck) deleteOrphanReport(ctx context.Context,
	log logr.Logger, rk struct {
		gvr      schema.GroupVersionResource
		kind     string
		resource string
	}, obj *unstructured.Unstructured) bool {

	err := p.Dyn.Resource(rk.gvr).Namespace(obj.GetNamespace()).Delete(ctx,
		obj.GetName(), kube.UIDDeleteOptions(obj.GetUID(), ""))
	switch {
	case err == nil:
		ephemeralReportsDeletedTotal.WithLabelValues(rk.kind).Inc()
		log.Info("DELETE: orphaned report — owner gone",
			"kind", rk.kind, "object", obj.GetNamespace()+"/"+obj.GetName())
		return true
	case apierrors.IsNotFound(err):
		return true // already gone — GC achieved, budget consumed
	case apierrors.IsForbidden(err):
		// Expected until the RBAC wave grants delete on the report
		// CRDs — log and skip without burning a run error.
		log.Info("WARN: orphan report delete forbidden (RBAC pending)",
			"kind", rk.kind, "object", obj.GetNamespace()+"/"+obj.GetName())
		return false
	default:
		metrics.IncError(p.Name)
		log.Error(err, "orphan report delete failed",
			"kind", rk.kind, "object", obj.GetNamespace()+"/"+obj.GetName())
		return false
	}
}

// pruneHelmSecrets counts helm release secrets into the census and
// caps superseded revisions per release. This is parallel logic to
// helmrelease-unlocker's pruneSupersededSecrets — that one is a
// method on the unlocker's private type and cannot be imported, so
// the parity contract is kept verbatim here: group by namespace +
// `name` label, only `status=superseded` secrets with a valid integer
// `version` label are prune candidates, the oldest beyond the cap are
// deleted with a UID precondition, and the highest-version secret of
// the release is NEVER touched (it stays the newest rollback point
// even when itself superseded). Returns the findings for the check's
// why string and the helm-excess gauge tuples for the ledger.
func (p *apiObjectSprawlReportGCCheck) pruneHelmSecrets(ctx context.Context,
	log logr.Logger, objectCurrent map[string][]string) ([]string, map[string][]string, error) {

	secrets, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm", Limit: probefw.HealthListPageSize},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return nil, nil, fmt.Errorf("list helm release secrets: %w", err)
	}
	type relKey struct{ ns, release string }
	byRelease := map[relKey][]*corev1.Secret{}
	perNS := map[string]int{}
	for i := range secrets {
		s := &secrets[i]
		if s.Type != corev1.SecretType(sprawlHelmSecretType) {
			continue
		}
		perNS[s.Namespace]++
		release := s.Labels["name"]
		if release == "" {
			continue
		}
		k := relKey{s.Namespace, release}
		byRelease[k] = append(byRelease[k], s)
	}
	for ns, count := range perNS {
		lv := []string{sprawlHelmSecretsResource, ns}
		objectCurrent[sprawlHelmSecretsResource+"/"+ns] = lv
		apiObjectCountGauge.WithLabelValues(lv...).Set(float64(count))
	}

	type supersededSecret struct {
		s *corev1.Secret
		v int
	}
	var findings []string
	helmCurrent := map[string][]string{}
	for k, relSecrets := range byRelease {
		highest := -1
		var superseded []supersededSecret
		for _, s := range relSecrets {
			v, verr := strconv.Atoi(s.Labels["version"])
			if verr != nil {
				continue // unversioned — never ours to judge
			}
			if v > highest {
				highest = v
			}
			if s.Labels["status"] == "superseded" {
				superseded = append(superseded, supersededSecret{s, v})
			}
		}
		excess := len(superseded) - sprawlMaxSuperseded
		if excess <= 0 {
			continue
		}
		lv := []string{k.ns, k.release}
		helmCurrent[k.ns+"/"+k.release] = lv
		helmSecretsExcessGauge.WithLabelValues(lv...).Set(float64(excess))
		findings = append(findings, fmt.Sprintf(
			"release %s/%s holds %d superseded secrets (cap %d)",
			k.ns, k.release, len(superseded), sprawlMaxSuperseded))
		sort.Slice(superseded, func(i, j int) bool {
			return superseded[i].v < superseded[j].v
		})
		toDelete := excess
		for _, cand := range superseded {
			if toDelete <= 0 {
				break
			}
			if cand.v == highest {
				continue // never touch the newest rollback point
			}
			if err := p.CS.CoreV1().Secrets(cand.s.Namespace).Delete(ctx,
				cand.s.Name, kube.UIDDeleteOptions(cand.s.UID, "")); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "superseded helm secret delete failed",
					"secret", cand.s.Namespace+"/"+cand.s.Name)
				continue // try the next-oldest instead of giving up
			}
			helmSecretsPrunedTotal.WithLabelValues(cand.s.Namespace).Inc()
			log.Info("DELETE: superseded helm release secret above keep cap",
				"release", k.ns+"/"+k.release, "secret", cand.s.Name,
				"version", cand.v)
			toDelete--
		}
	}
	return findings, helmCurrent, nil
}
