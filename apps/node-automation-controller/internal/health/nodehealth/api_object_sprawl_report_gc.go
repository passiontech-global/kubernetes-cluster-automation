// api_object_sprawl_report_gc.go — the
// api-object-sprawl-report-gc check: a per-namespace object census of
// the sprawl-prone report CRDs plus helm release secrets, a GC of
// orphaned trivy/policy reports (owner gone + aged out), and a cap on
// superseded helm revision secrets — the Kine/apiserver bloat guard.
package nodehealth

import (
	"context"
	"fmt"
	"sort"
	"strconv"
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

	// ownerSeen memoizes one sweep's owner-existence probes: a pod
	// with N containers produces N identical reports per kind, all
	// pointing at the same Pod/ReplicaSet owner — the N+1 Get storm
	// the map collapses to one lookup per distinct owner. Reset at
	// the top of every Run.
	ownerSeen map[string]bool
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
	if r := p.RequireDyn("api object sprawl gc"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	var objects, orphans, helmRep probefw.SweepReport
	orphanBudget := sprawlMaxOrphanDeletes
	p.ownerSeen = map[string]bool{}
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
			objects.Set(apiObjectCountGauge, float64(count),
				rk.resource+"/"+ns, []string{rk.resource, ns})
		}
		orphans.Set(ephemeralReportsOrphanedGauge, float64(orphaned),
			rk.kind, []string{rk.kind})
		if orphaned > 0 {
			objects.Find(fmt.Sprintf("%d orphaned %s", orphaned, rk.resource))
		}
	}

	if err := p.pruneHelmSecrets(ctx, log, &objects, &helmRep); err != nil {
		return probefw.Result{Infra: err}
	}

	objects.Close(&p.emittedObjects, apiObjectCountGauge.DeleteLabelValues)
	orphans.Close(&p.emittedOrphans, ephemeralReportsOrphanedGauge.DeleteLabelValues)
	helmRep.Close(&p.emittedHelm, helmSecretsExcessGauge.DeleteLabelValues)
	return objects.Verdict("api object sprawl: ", ", ")
}

// reportOwnerGone reports whether the report's controller owner is a
// Pod or ReplicaSet that provably no longer exists — the only owner
// kinds the GC deletes on. Reports with no controller owner, or an
// owner of any other kind (Job, StatefulSet, the report's own
// parent-report), fail closed: not evidence of orphanhood. Lookup
// errors other than NotFound also fail closed.
func (p *apiObjectSprawlReportGCCheck) reportOwnerGone(ctx context.Context,
	obj *unstructured.Unstructured) bool {

	// Only the Pod/ReplicaSet kinds are whitelisted — any other
	// shape (unresolvable, lookup error, no owner, object still
	// alive) fails closed as "not evidence of orphanhood".
	ref := metav1.GetControllerOf(obj)
	if ref == nil {
		return false
	}
	if p.ownerSeen == nil {
		p.ownerSeen = map[string]bool{} // lazy init — Run seeds it
	}
	key := ref.Kind + "/" + obj.GetNamespace() + "/" + ref.Name
	if gone, memo := p.ownerSeen[key]; memo {
		return gone // same owner already resolved this sweep
	}
	var gone bool
	if ref.Kind == "Pod" {
		// The sweep's shared pod census resolves Pod owners with
		// zero API calls; an unverifiable census fails closed the
		// same way a lookup error did (owner presumed alive).
		pods, err := p.AllPods(ctx)
		gone = err == nil &&
			probefw.PodFromList(pods, obj.GetNamespace(), ref.Name) == nil
	} else {
		gone, _ = probefw.OwnerGone(ctx, p.CS, obj.GetNamespace(),
			ref, "Pod", "ReplicaSet")
	}
	p.ownerSeen[key] = gone
	return gone
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
// even when itself superseded). Findings for the check's why string
// and the helm-excess gauge tuples are recorded on the reports.
func (p *apiObjectSprawlReportGCCheck) pruneHelmSecrets(ctx context.Context,
	log logr.Logger, objects, helmRep *probefw.SweepReport) error {

	// owner=helm,status=superseded server-side: every superseded
	// revision carries that label pair (helm v3 convention — the same
	// labels pruneSupersededSecrets and the test fixtures use), so
	// the live deployed/pending/failed revisions never cross the wire.
	// The census below therefore counts the superseded population —
	// the actual bloat the helm_release_secrets series exists to
	// track. The per-release "highest" guard still protects the
	// newest superseded revision (the rollback point), and a
	// non-superseded current revision was never a candidate anyway.
	secrets, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm,status=superseded",
		Limit:         probefw.HealthListPageSize},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list helm release secrets: %w", err)
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
		objects.Set(apiObjectCountGauge, float64(count),
			sprawlHelmSecretsResource+"/"+ns,
			[]string{sprawlHelmSecretsResource, ns})
	}

	type supersededSecret struct {
		s *corev1.Secret
		v int
	}
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
		helmRep.Set(helmSecretsExcessGauge, float64(excess),
			k.ns+"/"+k.release, []string{k.ns, k.release})
		objects.Find(fmt.Sprintf(
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
	return nil
}
