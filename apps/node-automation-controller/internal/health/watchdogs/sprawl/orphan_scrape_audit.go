// orphan_scrape_audit.go — the orphan scrape CRD auditor integrated into
// api-object-sprawl-report-gc: scans VMServiceScrape, VMPodScrape
// (operator.victoriametrics.com/v1beta1), ServiceMonitor, and PodMonitor
// (monitoring.coreos.com/v1) for unmanaged objects lacking ownerReferences
// and GitOps/Helm/KRO ownership labels older than 7 days. Emits
// node_automation_orphan_scrape_crd_count{kind,namespace,name} (detect-only
// by default) and supports opt-in UID-preconditioned GC (cap 5/sweep) via
// ORPHAN_SCRAPE_CRD_GC_ENABLED.
package sprawl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// orphanScrapeMinAge requires an unmanaged scrape CRD to sit untouched
	// for >7 days before it counts as orphaned (avoids flagging short-lived
	// debug/ad-hoc scrape configs).
	orphanScrapeMinAge = 7 * 24 * time.Hour

	// orphanScrapeMaxDeletes bounds opt-in GC deletions per sweep when
	// ORPHAN_SCRAPE_CRD_GC_ENABLED=true.
	orphanScrapeMaxDeletes = 5
)

var orphanScrapeKinds = []struct {
	gvr      schema.GroupVersionResource
	kind     string
	resource string
}{
	{kube.GVRVMServiceScrape, "vmservicescrape", "vmservicescrapes"},
	{kube.GVRVMPodScrape, "vmpodscrape", "vmpodscrapes"},
	{kube.GVRServiceMonitor, "servicemonitor", "servicemonitors"},
	{kube.GVRPodMonitor, "podmonitor", "podmonitors"},
}

var (
	orphanScrapeCRDCountGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_orphan_scrape_crd_count",
		Help: "1 for each unmanaged scrape CRD (VMServiceScrape/VMPodScrape/ServiceMonitor/PodMonitor) without ownerReferences or GitOps/Helm/KRO labels older than 7d.",
	}, []string{"kind", "namespace", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(orphanScrapeCRDCountGauge)
}

type orphanScrapeTarget struct {
	gvr       schema.GroupVersionResource
	kind      string
	ns        string
	name      string
	uid       types.UID
	createdAt time.Time
}

// isManagedScrapeObject reports whether obj has an ownerReference or carries
// GitOps/Helm/KRO management labels (or Helm release annotation).
func isManagedScrapeObject(obj metav1.Object) bool {
	if len(obj.GetOwnerReferences()) > 0 {
		return true
	}
	labels := obj.GetLabels()
	if labels["kustomize.toolkit.fluxcd.io/name"] != "" ||
		labels["helm.toolkit.fluxcd.io/name"] != "" ||
		labels["meta.helm.sh/release-name"] != "" {
		return true
	}
	switch strings.ToLower(labels["app.kubernetes.io/managed-by"]) {
	case "helm", "kro", "flux", "kustomize-controller":
		return true
	}
	if annos := obj.GetAnnotations(); annos["meta.helm.sh/release-name"] != "" {
		return true
	}
	return false
}

// auditOrphanScrapeCRDs scans VictoriaMetrics and Prometheus Operator scrape
// CRDs for unmanaged >7d orphans. Absent CRDs and 403 Forbidden responses
// fail open (skip quietly). Findings land on objects and gauge series on
// scrapeRep; when orphanScrapeGCEnabled is true, up to orphanScrapeMaxDeletes
// (5) orphans are UID-preconditioned deleted per sweep.
func (p *apiObjectSprawlReportGCCheck) auditOrphanScrapeCRDs(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	objects, scrapeRep *probefw.SweepReport,
) error {
	var targets []orphanScrapeTarget
	for _, sk := range orphanScrapeKinds {
		items, err := kube.ListPartialOrFallback(ctx, p.Meta, p.CS, p.Dyn,
			sk.gvr, metav1.NamespaceAll,
			metav1.ListOptions{
				Limit:           probefw.HealthListPageSize,
				ResourceVersion: "0",
			})
		switch {
		case kube.IsCRDAbsent(err) || apierrors.IsForbidden(err):
			log.V(1).Info("orphan scrape audit skipped (CRD absent or 403)",
				"resource", sk.resource, "error", err)
			continue
		case err != nil:
			return fmt.Errorf("list %s: %w", sk.resource, err)
		}
		for i := range items {
			obj := &items[i]
			if obj.GetDeletionTimestamp() != nil || obj.GetCreationTimestamp().Time.IsZero() {
				continue
			}
			if isManagedScrapeObject(obj) {
				continue
			}
			if now.Sub(obj.GetCreationTimestamp().Time) <= orphanScrapeMinAge {
				continue
			}
			ns, name := obj.GetNamespace(), obj.GetName()
			key := sk.kind + "/" + ns + "/" + name
			scrapeRep.Set(orphanScrapeCRDCountGauge, 1, key, []string{sk.kind, ns, name})
			objects.Find(fmt.Sprintf("orphan scrape %s %s/%s (>7d unmanaged)", sk.kind, ns, name))
			targets = append(targets, orphanScrapeTarget{
				gvr:       sk.gvr,
				kind:      sk.kind,
				ns:        ns,
				name:      name,
				uid:       obj.GetUID(),
				createdAt: obj.GetCreationTimestamp().Time,
			})
		}
	}

	if p.orphanScrapeGCEnabled && len(targets) > 0 {
		_, _, capped := reap.Sweep(ctx, log, targets, reap.Options[orphanScrapeTarget]{
			Cap: orphanScrapeMaxDeletes,
			Less: func(a, b orphanScrapeTarget) bool {
				if !a.createdAt.Equal(b.createdAt) {
					return a.createdAt.Before(b.createdAt)
				}
				if c := strings.Compare(a.kind, b.kind); c != 0 {
					return c < 0
				}
				if c := strings.Compare(a.ns, b.ns); c != 0 {
					return c < 0
				}
				if c := strings.Compare(a.name, b.name); c != 0 {
					return c < 0
				}
				return a.uid < b.uid
			},
			LogTarget: func(log logr.Logger, t orphanScrapeTarget) {
				log.Info("DELETE: orphan scrape CRD (>7d unmanaged)",
					"kind", t.kind, "object", t.ns+"/"+t.name, "uid", t.uid)
			},
			Delete: func(ctx context.Context, t orphanScrapeTarget) error {
				return p.Dyn.Resource(t.gvr).Namespace(t.ns).Delete(ctx,
					t.name, kube.UIDDeleteOptions(t.uid, ""))
			},
			OnError: func(log logr.Logger, t orphanScrapeTarget, err error) {
				switch {
				case apierrors.IsNotFound(err):
					log.Info("SKIP: orphan scrape CRD already gone",
						"kind", t.kind, "object", t.ns+"/"+t.name)
				case apierrors.IsConflict(err):
					log.Info("SKIP: orphan scrape CRD recreated since list — UID precondition fired",
						"kind", t.kind, "object", t.ns+"/"+t.name)
				case apierrors.IsForbidden(err):
					log.Info("WARN: orphan scrape CRD delete forbidden (RBAC pending)",
						"kind", t.kind, "object", t.ns+"/"+t.name)
				default:
					metrics.IncError(p.Name)
					log.Error(err, "orphan scrape CRD delete failed",
						"kind", t.kind, "object", t.ns+"/"+t.name)
				}
			},
		})
		if capped {
			log.Info("orphan scrape CRD GC hit per-sweep delete cap",
				"cap", orphanScrapeMaxDeletes, "candidates", len(targets))
		}
	}
	return nil
}
