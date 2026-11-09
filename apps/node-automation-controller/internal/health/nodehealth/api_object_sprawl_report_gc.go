// api_object_sprawl_report_gc.go — the
// api-object-sprawl-report-gc check: a per-namespace object census of
// the sprawl-prone report CRDs plus helm release secrets, a GC of
// orphaned trivy/policy reports (owner gone + aged out), and a cap on
// superseded helm revision secrets — the Kine/apiserver bloat guard.
package nodehealth

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
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
	// emittedLargeObjects tracks the kine large-object series
	// ("kind/namespace/name") — objects that shrink or vanish get
	// their series pruned next sweep.
	emittedLargeObjects state.GaugeLedger[string]

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

// sprawlCIKinds is the census half plus, since rollout-scale-flap, the
// completed-CR GC half: CI/CD CRs that pile up when their operators
// run without retention (Tekton prune keep cap unset, Shipwright
// succeededLimit/failedLimit absent). Counted into the same
// api-object census. gcCompleted kinds additionally GC their
// TERMINAL-phase objects past sprawlOrphanMinAge (argo rollouts'
// AnalysisRun/Experiment never delete their Successful/Failed/
// Error/Inconclusive records — they accumulate forever, one per
// canary step) — still NEVER owner-orphan-GC'd (reportOwnerGone does
// not apply to operator-owned records). An absent CRD (a cluster
// without Tekton, Shipwright or Argo Rollouts) skips silently.
var sprawlCIKinds = []struct {
	gvr      schema.GroupVersionResource
	kind     string
	resource string
	// gcCompleted marks kinds whose terminal-phase objects are GC'd
	// past sprawlOrphanMinAge (rollout-scale-flap: argo AnalysisRun/Experiment).
	gcCompleted bool
}{
	{kube.GVRTektonPipelineRun, "pipelinerun", "pipelineruns", false},
	{kube.GVRTektonTaskRun, "taskrun", "taskruns", false},
	{kube.GVRShipwrightBuildRun, "buildrun", "buildruns", false},
	{kube.GVRArgoAnalysisRun, "analysisrun", "analysisruns", true},
	{kube.GVRArgoExperiment, "experiment", "experiments", true},
}

// argoCompletedPhases are the terminal AnalysisRun/Experiment
// status.phase values — anything still Pending/Running is a live
// analysis and must never be GC'd.
var argoCompletedPhases = map[string]bool{
	"Successful": true, "Failed": true, "Error": true, "Inconclusive": true,
}

// sprawlKindRef is the (gvr, kind, resource) triple deleteOrphanReport
// needs — a named stand-in for both tables' anonymous element shapes.
type sprawlKindRef struct {
	gvr      schema.GroupVersionResource
	kind     string
	resource string
}

// sprawlCIMax is the CI/CD sprawl ceiling: past it the cluster's
// build-system CR population alone is apiserver/Kine bloat — the
// retention knobs (TektonConfig keep, Build succeededLimit/
// failedLimit) are missing or too loose.
const sprawlCIMax = 1000

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
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		apiObjectCountGauge,
		ephemeralReportsOrphanedGauge,
		ephemeralReportsDeletedTotal)
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

	var objects, orphans, helmRep, kineRep probefw.SweepReport
	orphanBudget := sprawlMaxOrphanDeletes
	p.ownerSeen = map[string]bool{}
	for _, rk := range sprawlReportKinds {
		// The snapshot's per-GVR census: trivy emits one report per
		// workload revision, so an unpaginated List is exactly the
		// etcd-serializes-everything shape this check exists to
		// fight. The raw apiserver error is memoized verbatim — the
		// IsNotFound/NoMatch interpretation stays here.
		items, err := p.AllUnstructured(ctx, rk.gvr)
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
		for i := range items {
			obj := &items[i]
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
			if p.deleteOrphanReport(ctx, log,
				sprawlKindRef{rk.gvr, rk.kind, rk.resource}, obj) {
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

	// CI/CD CR census — same per-namespace emission, no GC: the
	// finding fires when the combined build-system CR population
	// crosses the sprawl ceiling (retention knobs missing upstream).
	ciTotal := 0
	for _, rk := range sprawlCIKinds {
		items, err := p.AllUnstructured(ctx, rk.gvr)
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // CRD absent on this cluster — skip silently
		case err != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.resource, err)}
		}
		perNS := map[string]int{}
		completed := 0
		for i := range items {
			obj := &items[i]
			perNS[obj.GetNamespace()]++
			ciTotal++
			// rollout-scale-flap — terminal-phase argo records past the retention
			// threshold GC like the orphan reports: same budget, same
			// UID-preconditioned delete, same evidence surface. The
			// phase test gates it — a Running/Pending analysis is a
			// live canary gate.
			if !rk.gcCompleted ||
				now.Sub(obj.GetCreationTimestamp().Time) < sprawlOrphanMinAge {
				continue
			}
			phase, _ := kube.NestedString(obj.Object, "status", "phase")
			if !argoCompletedPhases[phase] {
				continue
			}
			completed++
			if orphanBudget <= 0 {
				continue // GC capped this cycle — still counted
			}
			if p.deleteOrphanReport(ctx, log,
				sprawlKindRef{rk.gvr, rk.kind, rk.resource}, obj) {
				orphanBudget--
			}
		}
		for ns, count := range perNS {
			objects.Set(apiObjectCountGauge, float64(count),
				rk.resource+"/"+ns, []string{rk.resource, ns})
		}
		if completed > 0 {
			// Same evidence surface as the report GC: the per-kind
			// orphaned gauge and a sweep finding per surviving batch.
			orphans.Set(ephemeralReportsOrphanedGauge, float64(completed),
				rk.kind, []string{rk.kind})
			objects.Find(fmt.Sprintf("%d completed %s GC'd", completed, rk.resource))
		}
	}
	if ciTotal > sprawlCIMax {
		objects.Find(fmt.Sprintf(
			"%d CI/CD CRs cluster-wide (>%d — Tekton/Shipwright retention missing)",
			ciTotal, sprawlCIMax))
	}

	if err := p.pruneHelmSecrets(ctx, log, &objects, &helmRep); err != nil {
		return probefw.Result{Infra: err}
	}

	// Kine large-object census — cluster-wide ConfigMap/Secret size
	// census on ITS OWN GaugeScope (kineRep): its tuples
	// ("kind/ns/name") live on kineLargeObjectBytesGauge, a different
	// gauge with different label values than the counts report's
	// "resource/ns" tuples — reconciling one ledger against the
	// other's report would cross-prune series and cross-pollute the
	// keyspaces. Findings still land on the shared verdict via
	// objects. Same failed-read posture as the report census above:
	// bail before any ledger Prune so live series are not dropped on
	// a flap.
	if err := p.auditKineLargeObjects(ctx, &objects, &kineRep); err != nil {
		return probefw.Result{Infra: err}
	}

	objects.Close(&p.emittedObjects, apiObjectCountGauge.DeleteLabelValues)
	orphans.Close(&p.emittedOrphans, ephemeralReportsOrphanedGauge.DeleteLabelValues)
	helmRep.Close(&p.emittedHelm, helmSecretsExcessGauge.DeleteLabelValues)
	kineRep.Close(&p.emittedLargeObjects, kineLargeObjectBytesGauge.DeleteLabelValues)
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

// deleteOrphanReport removes one orphaned report (or, since rollout-scale-flap,
// one completed argo analysis/experiment) with a UID precondition —
// the "delete the object I vetted" shape every reaper in this
// codebase uses.
func (p *apiObjectSprawlReportGCCheck) deleteOrphanReport(ctx context.Context,
	log logr.Logger, rk sprawlKindRef, obj *unstructured.Unstructured) bool {

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
		// Expected until the RBAC rollout grants delete on the report
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
