// kargo_promotion_health.go — the kargo-promotion-health check
// (kargo-promotion-health): Kargo Promotion stalls, Warehouse refresh starvation
// and Argo Rollouts AnalysisRun zombies. operator-workqueue-watchdog
// only proves the kargo controller keeps reconciling; this check
// catches the work objects it strands: a Promotion parked
// Running/Pending past the hour (git push conflict, PR-merge wait,
// a hung ArgoCD sync hook), a Warehouse Ready=False past the half
// hour (registry auth or rate-limit starving the artifact feed —
// gets a kargo.akuity.io/refresh nudge under a 1h persisted
// cooldown), and a Rollouts verification AnalysisRun still Running
// after an hour. Every CRD family tolerates absence independently —
// Kargo/Rollouts simply may not be installed.
package gitops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// kargoPromotionHealthCheck is the kargo-promotion-health stall watchdog.
type kargoPromotionHealthCheck struct {
	*probefw.Deps

	// warehouseRefreshHealed: "ns/name" → last refresh nudge — the
	// in-RAM half of the 1h persisted cooldown (the durable half is
	// kube.AnnoLastKargoRefresh on the Warehouse itself).
	warehouseRefreshHealed state.CooldownSet
	// emittedXxx: gauge tuples held at 1 — a tuple not re-seen gets
	// DeleteLabelValues'd rather than leaking a stale 1 (one
	// GaugeLedger per vec).
	emittedPromotions   state.GaugeLedger[string]
	emittedWarehouses   state.GaugeLedger[string]
	emittedAnalysisRuns state.GaugeLedger[string]
}

// NewKargoPromotionHealthCheck builds the kargo-promotion-health check — its state
// is the refresh cooldown plus the three emitted-gauge ledgers
// (zero values usable).
func NewKargoPromotionHealthCheck(d *probefw.Deps) probefw.Check {
	return &kargoPromotionHealthCheck{Deps: d}
}

const (
	CheckNameKargoPromotionHealth = "kargo-promotion-health"

	// kargo-promotion-health — kargo-promotion-health knobs.
	kargoPromotionStuckMinAge  = 60 * time.Minute
	kargoWarehouseUnhealthyAge = 30 * time.Minute
	kargoWarehouseRefreshCool  = time.Hour
	argoAnalysisRunStuckMinAge = 60 * time.Minute
)

var (
	// kargo-promotion-health — a Promotion holding a non-terminal phase past the
	// hour.
	kargoPromotionStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_kargo_promotion_stuck",
		Help: "1 while a Kargo Promotion stays in Running/Pending phase for >=60m — kargo-promotion-health.",
	}, []string{"namespace", "name", "stage"})

	// kargo-promotion-health — a Warehouse Ready=False past the half hour (registry
	// auth / rate-limit starving the artifact feed).
	kargoWarehouseUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_kargo_warehouse_unhealthy",
		Help: "1 while a Kargo Warehouse reports Ready=False for >=30m — kargo-promotion-health.",
	}, []string{"namespace", "name"})

	// kargo-promotion-health — an Argo Rollouts verification AnalysisRun still
	// Running past the hour.
	argoAnalysisRunStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_analysisrun_stuck",
		Help: "1 while an Argo Rollouts AnalysisRun stays in Running phase for >=60m — kargo-promotion-health.",
	}, []string{"namespace", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		kargoPromotionStuckGauge,
		kargoWarehouseUnhealthyGauge,
		argoAnalysisRunStuckGauge)
}

// checkKargoPromotionHealth sweeps the three stall families. Each
// dyn List tolerates NotFound/NoMatch independently — the CRD set
// varies per cluster, and a missing family is "not installed", never
// a verdict. The object's whole lifetime IS the promotion/analysis
// attempt (Kargo and Rollouts stamp no per-phase transition time),
// so CreationTimestamp is the stuck clock.
func (p *kargoPromotionHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	if r := p.RequireDyn("kargo promotion check"); r != nil {
		return *r
	}
	now := p.Now()
	p.warehouseRefreshHealed.PruneExpired(now, kargoWarehouseRefreshCool)

	var promRep, whRep, arRep probefw.SweepReport

	// Promotions — Running/Pending past the hour. Each family reads
	// the snapshot's per-GVR census; the RAW error memoizes and the
	// NotFound/NoMatch tolerance stays per family.
	promotions, err := p.AllUnstructured(ctx, kube.GVRKargoPromotion)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent — Kargo not installed; the family skips.
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list kargo promotions: %w", err)}
	default:
		for i := range promotions {
			pr := &promotions[i]
			phase, _ := kube.NestedString(pr.Object, "status", "phase")
			if !kargoPhaseStuck(phase) {
				continue
			}
			if now.Sub(pr.GetCreationTimestamp().Time) < kargoPromotionStuckMinAge {
				continue
			}
			stage, _ := kube.NestedString(pr.Object, "spec", "stage")
			ns, name := pr.GetNamespace(), pr.GetName()
			key := ns + "/" + name
			promRep.Emit(kargoPromotionStuckGauge, key,
				[]string{ns, name, stage},
				fmt.Sprintf("%s(phase=%s stage=%s)", key, phase, stage))
		}
	}

	// Warehouses — Ready=False past the half hour; each qualifying
	// object also gets the refresh nudge under the persisted
	// cooldown.
	warehouses, err := p.AllUnstructured(ctx, kube.GVRKargoWarehouse)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list kargo warehouses: %w", err)}
	default:
		for i := range warehouses {
			wh := &warehouses[i]
			c, ok := kube.ConditionOf(wh.Object, "Ready")
			if !ok || c.Status != "False" {
				continue
			}
			// The window reads the condition's own clock — no
			// timestamp means the age cannot be proven, so stay
			// quiet rather than remediate blind (the
			// flux-helmrelease-retries posture).
			if c.LastTransitionTime.IsZero() ||
				now.Sub(c.LastTransitionTime) < kargoWarehouseUnhealthyAge {
				continue
			}
			ns, name := wh.GetNamespace(), wh.GetName()
			key := ns + "/" + name
			whRep.Emit(kargoWarehouseUnhealthyGauge, key,
				[]string{ns, name}, key+"(ready=false)")
			p.maybeRefreshKargoWarehouse(ctx, log, wh, key, now)
		}
	}

	// AnalysisRuns — Running past the hour. Same lifetime-clock
	// reasoning as Promotions.
	analysisRuns, err := p.AllUnstructured(ctx, kube.GVRArgoAnalysisRun)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list argo analysisruns: %w", err)}
	default:
		for i := range analysisRuns {
			ar := &analysisRuns[i]
			phase, _ := kube.NestedString(ar.Object, "status", "phase")
			if !strings.EqualFold(phase, "Running") {
				continue
			}
			if now.Sub(ar.GetCreationTimestamp().Time) < argoAnalysisRunStuckMinAge {
				continue
			}
			ns, name := ar.GetNamespace(), ar.GetName()
			key := ns + "/" + name
			arRep.Emit(argoAnalysisRunStuckGauge, key,
				[]string{ns, name}, key+"(phase=Running)")
		}
	}

	promRep.Close(&p.emittedPromotions, kargoPromotionStuckGauge.DeleteLabelValues)
	whRep.Close(&p.emittedWarehouses, kargoWarehouseUnhealthyGauge.DeleteLabelValues)
	arRep.Close(&p.emittedAnalysisRuns, argoAnalysisRunStuckGauge.DeleteLabelValues)
	return probefw.WhyFold(
		probefw.Section("promotions running/pending >=%s: %s",
			promRep.Sorted(), kargoPromotionStuckMinAge),
		probefw.Section("warehouses not ready >=%s: %s",
			whRep.Sorted(), kargoWarehouseUnhealthyAge),
		probefw.Section("analysisruns running >=%s: %s",
			arRep.Sorted(), argoAnalysisRunStuckMinAge))
}

// kargoPhaseStuck reports whether a Promotion phase is one of the
// non-terminal, wedge-able states — Succeeded/Failed/Errored/
// Aborted all end the attempt on their own.
func kargoPhaseStuck(phase string) bool {
	return strings.EqualFold(phase, "Running") ||
		strings.EqualFold(phase, "Pending")
}

// maybeRefreshKargoWarehouse stamps kargo.akuity.io/refresh on a
// starved Warehouse so the controller retries artifact discovery —
// 1h per-Warehouse cooldown, the wider of the in-RAM ledger and the
// last-kargo-refresh stamp the previous patch (ours or an
// operator's) left behind. The write side stays hand-rolled:
// StampPersisted emits a single-annotation patch and this nudge
// needs AnnoKargoRefresh AND AnnoLastKargoRefresh landed together —
// the same shape maybePatchHRRetry uses for its annotation triple.
// Annotation nudges are non-destructive: no maintenance mutex.
func (p *kargoPromotionHealthCheck) maybeRefreshKargoWarehouse(ctx context.Context,
	log logr.Logger, wh *unstructured.Unstructured, key string, now time.Time) {

	if heal.PersistedCooledDown(&p.warehouseRefreshHealed, wh,
		kube.AnnoLastKargoRefresh, key, kargoWarehouseRefreshCool, now) {
		return
	}
	token := now.UTC().Format(time.RFC3339)
	patch, err := kube.MergePatchAnnos(map[string]any{
		kube.AnnoKargoRefresh:     token,
		kube.AnnoLastKargoRefresh: token,
	})
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "marshal kargo warehouse refresh patch failed",
			"warehouse", key)
		return
	}
	if _, err := p.Dyn.Resource(kube.GVRKargoWarehouse).
		Namespace(wh.GetNamespace()).Patch(ctx, wh.GetName(),
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "kargo warehouse refresh patch failed",
			"warehouse", key)
		return
	}
	p.warehouseRefreshHealed.Stamp(key, now)
	log.Info("PATCH: kargo warehouse refresh annotation",
		"warehouse", key)
}
