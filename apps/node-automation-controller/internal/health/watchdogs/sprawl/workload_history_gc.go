// workload_history_gc.go — extended API object sprawl census +
// bounded auto-GC for api-object-sprawl-report-gc (Wave 4C #11):
//   - 0-replica ReplicaSets (>24h) whose owning Deployment is gone or
//     that exceed max(revisionHistoryLimit, 10) for a live Deployment
//     (always preserving the newest N),
//   - orphan ControllerRevisions (>24h) whose owning StatefulSet/DaemonSet
//     is gone (verified via live Get),
//   - orphan legacy kubernetes.io/service-account-token Secrets (>24h)
//     whose referenced ServiceAccount is gone or has a mismatched UID.
//
// Deletion is bounded to sprawlMaxHistoryDeletes (30) per sweep via
// reap.Sweep + kube.UIDDeleteOptions, gated by
// NODE_AUTOMATION_SPRAWL_HISTORY_GC_ENABLED (default true, resolved once
// at check construction). Read/delete 403 Forbidden errors skip
// gracefully without incrementing controller error counters.
package sprawl

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	sprawlHistoryMinAge     = 24 * time.Hour
	sprawlMaxHistoryDeletes = 30
	sprawlDefaultRevHistory = int32(10)

	sprawlKindReplicaSetZero      = "replicaset_zero"
	sprawlKindControllerRevOrphan = "controllerrevision_orphan"
	sprawlKindSATokenOrphan       = "sa_token_orphan"
)

var (
	apiObjectSprawlCountGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_api_object_sprawl_count",
		Help: "Verified >24h extended sprawl-GC candidates (0-replica ReplicaSets, orphan ControllerRevisions, orphan SA-token Secrets), by kind.",
	}, []string{"kind"})

	sprawlHistoryDeletedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_sprawl_history_deleted_total",
		Help: "Orphaned or excess-history objects deleted by the extended sprawl GC, by kind.",
	}, []string{"kind"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		apiObjectSprawlCountGauge,
		sprawlHistoryDeletedTotal,
	)
}

type historyGCTarget struct {
	kind      string
	ns        string
	name      string
	uid       types.UID
	createdAt time.Time
}

type depLookup struct {
	found     bool
	forbidden bool
	err       error
	dep       *appsv1.Deployment
}

type ownerUIDLookup struct {
	notFound  bool
	forbidden bool
	err       error
	uid       types.UID
}

func (p *apiObjectSprawlReportGCCheck) carryHistoryKind(historyRep *probefw.SweepReport, kind string) {
	for k, lv := range p.emittedHistorySprawl.Last() {
		if k == kind {
			historyRep.Carry(k, lv)
		}
	}
}

func (p *apiObjectSprawlReportGCCheck) gcWorkloadHistorySprawl(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	objects, historyRep *probefw.SweepReport,
) error {
	rsTargets, err := p.collectZeroReplicaSetTargets(ctx, log, now, historyRep)
	if err != nil {
		return err
	}
	crTargets, err := p.collectOrphanControllerRevisions(ctx, log, now, historyRep)
	if err != nil {
		return err
	}
	saTargets, err := p.collectOrphanSATokenSecrets(ctx, log, now, historyRep)
	if err != nil {
		return err
	}

	kindBatches := []struct {
		kind    string
		targets []historyGCTarget
	}{
		{sprawlKindReplicaSetZero, rsTargets},
		{sprawlKindControllerRevOrphan, crTargets},
		{sprawlKindSATokenOrphan, saTargets},
	}

	var allTargets []historyGCTarget
	for _, b := range kindBatches {
		if len(b.targets) == 0 {
			continue
		}
		historyRep.Set(apiObjectSprawlCountGauge, float64(len(b.targets)),
			b.kind, []string{b.kind})
		objects.Find(fmt.Sprintf("%d %s sprawl", len(b.targets), b.kind))
		allTargets = append(allTargets, b.targets...)
	}

	if !p.historyGCEnabled || len(allTargets) == 0 {
		return nil
	}

	_, _, capped := reap.Sweep(ctx, log, allTargets, reap.Options[historyGCTarget]{
		Cap: sprawlMaxHistoryDeletes,
		Less: func(a, b historyGCTarget) bool {
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
		LogTarget: func(log logr.Logger, t historyGCTarget) {
			log.Info("DELETE: extended sprawl GC",
				"kind", t.kind, "object", t.ns+"/"+t.name, "uid", t.uid)
		},
		Delete: func(ctx context.Context, t historyGCTarget) error {
			opts := kube.UIDDeleteOptions(t.uid, "")
			var derr error
			switch t.kind {
			case sprawlKindReplicaSetZero:
				derr = p.CS.AppsV1().ReplicaSets(t.ns).Delete(ctx, t.name, opts)
			case sprawlKindControllerRevOrphan:
				derr = p.CS.AppsV1().ControllerRevisions(t.ns).Delete(ctx, t.name, opts)
			case sprawlKindSATokenOrphan:
				derr = p.CS.CoreV1().Secrets(t.ns).Delete(ctx, t.name, opts)
			default:
				return fmt.Errorf("unknown sprawl history target kind %q", t.kind)
			}
			if derr == nil {
				sprawlHistoryDeletedTotal.WithLabelValues(t.kind).Inc()
			}
			return derr
		},
		OnError: func(log logr.Logger, t historyGCTarget, err error) {
			switch {
			case apierrors.IsNotFound(err):
				log.Info("SKIP: "+t.kind+" already gone", "object", t.ns+"/"+t.name)
			case apierrors.IsConflict(err):
				log.Info("SKIP: "+t.kind+" recreated since list — UID precondition fired", "object", t.ns+"/"+t.name)
			case apierrors.IsForbidden(err):
				log.Info("WARN: "+t.kind+" delete forbidden (RBAC pending)", "object", t.ns+"/"+t.name)
			default:
				metrics.IncError(p.Name)
				log.Error(err, t.kind+" delete failed", "object", t.ns+"/"+t.name)
			}
		},
	})
	if capped {
		log.Info("extended sprawl GC hit per-sweep delete cap",
			"cap", sprawlMaxHistoryDeletes, "candidates", len(allTargets))
	}
	return nil
}

func (p *apiObjectSprawlReportGCCheck) collectZeroReplicaSetTargets(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	historyRep *probefw.SweepReport,
) ([]historyGCTarget, error) {
	rss, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.ReplicaSets(p.CS, metav1.NamespaceAll))
	switch {
	case apierrors.IsForbidden(err):
		log.V(1).Info("WARN: replicaset sprawl list skipped (403)", "error", err)
		p.carryHistoryKind(historyRep, sprawlKindReplicaSetZero)
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("list replicasets: %w", err)
	}

	type depGroup struct {
		keep int32
		rss  []*appsv1.ReplicaSet
	}

	depCache := map[string]depLookup{}
	liveGroups := map[string]*depGroup{}
	var targets []historyGCTarget

	for i := range rss {
		rs := &rss[i]
		if rs.DeletionTimestamp != nil || rs.CreationTimestamp.IsZero() {
			continue
		}
		if rs.Spec.Replicas == nil || *rs.Spec.Replicas != 0 || rs.Status.Replicas != 0 {
			continue
		}
		ref := metav1.GetControllerOf(rs)
		if ref == nil || ref.Kind != "Deployment" {
			continue
		}

		depKey := rs.Namespace + "/" + ref.Name
		dl, cached := depCache[depKey]
		if !cached {
			dep, gerr := p.CS.AppsV1().Deployments(rs.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(gerr):
				dl = depLookup{}
			case apierrors.IsForbidden(gerr):
				log.V(1).Info("WARN: deployment get skipped (403)", "deployment", depKey, "error", gerr)
				dl = depLookup{forbidden: true}
			case gerr != nil:
				log.V(1).Info("WARN: deployment get failed — fail closed", "deployment", depKey, "error", gerr)
				dl = depLookup{err: gerr}
			default:
				dl = depLookup{found: true, dep: dep}
			}
			depCache[depKey] = dl
		}

		if dl.forbidden || dl.err != nil {
			continue
		}
		if !dl.found || (ref.UID != "" && dl.dep.UID != "" && dl.dep.UID != ref.UID) {
			if now.Sub(rs.CreationTimestamp.Time) > sprawlHistoryMinAge {
				targets = append(targets, historyGCTarget{
					kind:      sprawlKindReplicaSetZero,
					ns:        rs.Namespace,
					name:      rs.Name,
					uid:       rs.UID,
					createdAt: rs.CreationTimestamp.Time,
				})
			}
			continue
		}

		// Group ALL 0-replica ReplicaSets for the live Deployment (including
		// <=24h revisions) BEFORE applying max(revisionHistoryLimit, 10).
		grp, ok := liveGroups[depKey]
		if !ok {
			keep := sprawlDefaultRevHistory
			if dl.dep.Spec.RevisionHistoryLimit != nil && *dl.dep.Spec.RevisionHistoryLimit > keep {
				keep = *dl.dep.Spec.RevisionHistoryLimit
			}
			grp = &depGroup{keep: keep}
			liveGroups[depKey] = grp
		}
		grp.rss = append(grp.rss, rs)
	}

	for _, grp := range liveGroups {
		if len(grp.rss) <= int(grp.keep) {
			continue
		}
		slices.SortFunc(grp.rss, func(a, b *appsv1.ReplicaSet) int {
			if !a.CreationTimestamp.Time.Equal(b.CreationTimestamp.Time) {
				if a.CreationTimestamp.Time.Before(b.CreationTimestamp.Time) {
					return -1
				}
				return 1
			}
			if c := cmp.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			return cmp.Compare(a.UID, b.UID)
		})
		excess := grp.rss[:len(grp.rss)-int(grp.keep)]
		for _, rs := range excess {
			if now.Sub(rs.CreationTimestamp.Time) > sprawlHistoryMinAge {
				targets = append(targets, historyGCTarget{
					kind:      sprawlKindReplicaSetZero,
					ns:        rs.Namespace,
					name:      rs.Name,
					uid:       rs.UID,
					createdAt: rs.CreationTimestamp.Time,
				})
			}
		}
	}

	return targets, nil
}

func (p *apiObjectSprawlReportGCCheck) collectOrphanControllerRevisions(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	historyRep *probefw.SweepReport,
) ([]historyGCTarget, error) {
	crs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.ControllerRevisions(p.CS, metav1.NamespaceAll))
	switch {
	case apierrors.IsForbidden(err):
		log.V(1).Info("WARN: controllerrevision sprawl list skipped (403)", "error", err)
		p.carryHistoryKind(historyRep, sprawlKindControllerRevOrphan)
		return nil, nil
	case apierrors.IsNotFound(err):
		log.V(1).Info("WARN: controllerrevision endpoint not found (404)", "error", err)
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("list controllerrevisions: %w", err)
	}

	ownerCache := map[string]ownerUIDLookup{}
	var targets []historyGCTarget

	for i := range crs {
		cr := &crs[i]
		if cr.DeletionTimestamp != nil || cr.CreationTimestamp.IsZero() {
			continue
		}
		if now.Sub(cr.CreationTimestamp.Time) <= sprawlHistoryMinAge {
			continue
		}
		ref := metav1.GetControllerOf(cr)
		if ref == nil || (ref.Kind != "StatefulSet" && ref.Kind != "DaemonSet") {
			continue
		}

		cacheKey := ref.Kind + "/" + cr.Namespace + "/" + ref.Name
		ol, cached := ownerCache[cacheKey]
		if !cached {
			var ownerUID types.UID
			var gerr error
			switch ref.Kind {
			case "StatefulSet":
				sts, err := p.CS.AppsV1().StatefulSets(cr.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
				if err == nil {
					ownerUID = sts.UID
				}
				gerr = err
			case "DaemonSet":
				ds, err := p.CS.AppsV1().DaemonSets(cr.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
				if err == nil {
					ownerUID = ds.UID
				}
				gerr = err
			}
			switch {
			case apierrors.IsNotFound(gerr):
				ol = ownerUIDLookup{notFound: true}
			case apierrors.IsForbidden(gerr):
				log.V(1).Info("WARN: controllerrevision owner get skipped (403)", "owner", cacheKey, "error", gerr)
				ol = ownerUIDLookup{forbidden: true}
			case gerr != nil:
				log.V(1).Info("WARN: controllerrevision owner get failed — fail closed", "owner", cacheKey, "error", gerr)
				ol = ownerUIDLookup{err: gerr}
			default:
				ol = ownerUIDLookup{uid: ownerUID}
			}
			ownerCache[cacheKey] = ol
		}

		if ol.forbidden || ol.err != nil {
			continue
		}
		if ol.notFound || (ref.UID != "" && ol.uid != "" && ol.uid != ref.UID) {
			targets = append(targets, historyGCTarget{
				kind:      sprawlKindControllerRevOrphan,
				ns:        cr.Namespace,
				name:      cr.Name,
				uid:       cr.UID,
				createdAt: cr.CreationTimestamp.Time,
			})
		}
	}

	return targets, nil
}

func (p *apiObjectSprawlReportGCCheck) collectOrphanSATokenSecrets(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	historyRep *probefw.SweepReport,
) ([]historyGCTarget, error) {
	saCache := map[string]ownerUIDLookup{}
	var targets []historyGCTarget

	err := kube.ListEach(ctx,
		metav1.ListOptions{
			Limit:         probefw.HealthListPageSize,
			FieldSelector: "type=" + string(corev1.SecretTypeServiceAccountToken),
		},
		kube.Secrets(p.CS, metav1.NamespaceAll),
		func(items []corev1.Secret) error {
			for i := range items {
				s := &items[i]
				if s.DeletionTimestamp != nil || s.CreationTimestamp.IsZero() {
					continue
				}
				if s.Type != corev1.SecretTypeServiceAccountToken {
					continue
				}
				if now.Sub(s.CreationTimestamp.Time) <= sprawlHistoryMinAge {
					continue
				}
				saName := s.Annotations[corev1.ServiceAccountNameKey]
				if saName == "" {
					continue
				}

				cacheKey := s.Namespace + "/" + saName
				ol, cached := saCache[cacheKey]
				if !cached {
					sa, gerr := p.CS.CoreV1().ServiceAccounts(s.Namespace).Get(ctx, saName, metav1.GetOptions{})
					switch {
					case apierrors.IsNotFound(gerr):
						ol = ownerUIDLookup{notFound: true}
					case apierrors.IsForbidden(gerr):
						log.V(1).Info("WARN: serviceaccount get skipped (403)", "serviceaccount", cacheKey, "error", gerr)
						ol = ownerUIDLookup{forbidden: true}
					case gerr != nil:
						log.V(1).Info("WARN: serviceaccount get failed — fail closed", "serviceaccount", cacheKey, "error", gerr)
						ol = ownerUIDLookup{err: gerr}
					default:
						ol = ownerUIDLookup{uid: sa.UID}
					}
					saCache[cacheKey] = ol
				}

				if ol.forbidden || ol.err != nil {
					continue
				}
				saUID := s.Annotations[corev1.ServiceAccountUIDKey]
				if ol.notFound || (saUID != "" && ol.uid != "" && string(ol.uid) != saUID) {
					targets = append(targets, historyGCTarget{
						kind:      sprawlKindSATokenOrphan,
						ns:        s.Namespace,
						name:      s.Name,
						uid:       s.UID,
						createdAt: s.CreationTimestamp.Time,
					})
				}
			}
			return nil
		})
	switch {
	case apierrors.IsForbidden(err):
		log.V(1).Info("WARN: sa-token secret sprawl list skipped (403)", "error", err)
		p.carryHistoryKind(historyRep, sprawlKindSATokenOrphan)
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("list service-account-token secrets: %w", err)
	}

	return targets, nil
}
