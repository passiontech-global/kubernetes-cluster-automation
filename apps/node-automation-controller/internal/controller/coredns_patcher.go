// coredns_patcher.go — port of the coredns-topology-spread CronJob
// (infrastructure/base/scaling/coredns/coredns-topology-spread.yaml in
// passiontech-fluxcd, plus the cicd override single-zone-topology-patch.yaml).
//
// Keeps deployment kube-system/coredns at the pinned probe timeouts,
// resources and topologySpreadConstraints. The Deployment is owned by
// the k0s stack applier, which reverts it on every apply — its stock
// manifest carries a required hostname podAntiAffinity (max 1 pod
// kube-dns per node) so a surge pod can never schedule, and the 1s
// default probe timeouts mass-kill pods under node load.
//
// Spread policy (config-driven, was ZONE_WHEN/ZONE_MIN_DOMAINS):
// zone = DoNotSchedule + minDomains=2 on multi-zone clusters —
// guarantees >=1 DNS backend per zone so service topology keeps
// resolving locally during an inter-DC degrade; cicd (single zone)
// runs ScheduleAnyway with no minDomains — DoNotSchedule on a
// 1-domain cluster would wedge the rollout forever. hostname =
// ScheduleAnyway: ~1 pod/node steady state, surge still schedules.
// nodeTaintsPolicy/nodeAffinityPolicy=Honor keep tainted/drained
// nodes out of the domain calculation so DoNotSchedule can't lock
// the rollout. The watch patches drift back in <1s; the 15m requeue
// replaces the old hourly crontab.
package controller

import (
	"context"
	"encoding/json"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

var (
	corednsWantReqCPU = resource.MustParse("25m")
	corednsWantReqMem = resource.MustParse("64Mi")
	corednsWantLimCPU = resource.MustParse("300m")
	corednsWantLimMem = resource.MustParse("256Mi")
)

type corednsPatcher struct {
	cs         kubernetes.Interface
	zoneWhen   string
	minDomains int
}

// SetupCoreDNSPatcher reconciles only the coredns Deployment (the
// informer sees every kube-system Deployment — the predicate pins
// ns/name). Clusters without the module (enabled=false, e.g. ones
// managing coredns themselves) skip registration entirely.
func SetupCoreDNSPatcher(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool, zoneWhen string, zoneMinDomains int) error {
	if !enabled {
		return nil
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("coredns-patcher").
		For(&appsv1.Deployment{}, builder.WithPredicates(
			predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetNamespace() == "kube-system" &&
					o.GetName() == "coredns"
			}))).
		Complete(&corednsPatcher{cs: cs, zoneWhen: zoneWhen, minDomains: zoneMinDomains})
}

func (r *corednsPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 15 * time.Minute}

	d, err := r.cs.AppsV1().Deployments("kube-system").
		Get(ctx, "coredns", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return res, nil // cluster without the k0s coredns addon
	}
	if err != nil {
		metrics.IncError("coredns-patcher")
		return ctrl.Result{}, err
	}

	if !corednsNeedsPatch(d, r.zoneWhen, r.minDomains) {
		log.Info("probes/resources/topology already pinned - nothing to do")
		return res, nil
	}
	patch, err := corednsPatchBody(r.zoneWhen, r.minDomains)
	if err != nil {
		metrics.IncError("coredns-patcher")
		return ctrl.Result{}, err
	}
	log.Info("coredns drifted - patching")
	if _, err := r.cs.AppsV1().Deployments("kube-system").Patch(ctx,
		"coredns", types.StrategicMergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError("coredns-patcher")
		return ctrl.Result{}, err
	}
	return res, nil
}

// corednsMinDomainsWanted gates minDomains onto DoNotSchedule only —
// the API rejects minDomains combined with ScheduleAnyway (the cicd
// override therefore runs ScheduleAnyway with minDomains disabled).
func corednsMinDomainsWanted(zoneWhen string, minDomains int) bool {
	return zoneWhen == string(corev1.DoNotSchedule) && minDomains > 0
}

// corednsNeedsPatch reports whether the Deployment lacks any pinned
// field — probe timeouts, requests/limits, cleared affinity, or the
// two wanted spread constraints. A missing coredns container counts
// as drifted (same as the shell's empty jsonpath probe).
func corednsNeedsPatch(d *appsv1.Deployment, zoneWhen string, minDomains int) bool {
	ps := d.Spec.Template.Spec
	for i := range ps.Containers {
		c := &ps.Containers[i]
		if c.Name != "coredns" {
			continue
		}
		if c.LivenessProbe == nil || c.LivenessProbe.TimeoutSeconds != 5 ||
			c.ReadinessProbe == nil || c.ReadinessProbe.TimeoutSeconds != 5 {
			return true
		}
		reqCPU := c.Resources.Requests[corev1.ResourceCPU]
		reqMem := c.Resources.Requests[corev1.ResourceMemory]
		limCPU := c.Resources.Limits[corev1.ResourceCPU]
		limMem := c.Resources.Limits[corev1.ResourceMemory]
		if reqCPU.Cmp(corednsWantReqCPU) != 0 ||
			reqMem.Cmp(corednsWantReqMem) != 0 ||
			limCPU.Cmp(corednsWantLimCPU) != 0 ||
			limMem.Cmp(corednsWantLimMem) != 0 {
			return true
		}
		if ps.Affinity != nil {
			return true
		}
		return !corednsTopologyOK(ps.TopologySpreadConstraints, zoneWhen, minDomains)
	}
	return true
}

// corednsTopologyOK requires both wanted constraints: zone per the
// configured whenUnsatisfiable/minDomains and hostname ScheduleAnyway,
// each selector k8s-app=kube-dns with Honor node-inclusion policies.
func corednsTopologyOK(tscs []corev1.TopologySpreadConstraint, zoneWhen string, minDomains int) bool {
	zoneOK, hostOK := false, false
	for _, c := range tscs {
		sel := c.LabelSelector != nil &&
			c.LabelSelector.MatchLabels["k8s-app"] == "kube-dns"
		if c.MaxSkew != 1 {
			continue
		}
		honor := c.NodeTaintsPolicy != nil &&
			*c.NodeTaintsPolicy == corev1.NodeInclusionPolicyHonor &&
			c.NodeAffinityPolicy != nil &&
			*c.NodeAffinityPolicy == corev1.NodeInclusionPolicyHonor
		switch c.TopologyKey {
		case "topology.kubernetes.io/zone":
			if c.WhenUnsatisfiable != corev1.UnsatisfiableConstraintAction(zoneWhen) ||
				!sel || !honor {
				continue
			}
			// minDomains can only exist under DoNotSchedule (API
			// validation), so the not-wanted case means nil.
			if corednsMinDomainsWanted(zoneWhen, minDomains) {
				zoneOK = c.MinDomains != nil && *c.MinDomains == int32(minDomains)
			} else {
				zoneOK = c.MinDomains == nil
			}
		case "kubernetes.io/hostname":
			if c.WhenUnsatisfiable == corev1.ScheduleAnyway && sel && honor {
				hostOK = true
			}
		}
	}
	return zoneOK && hostOK
}

// corednsPatchBody renders the strategic-merge patch — containers
// merge by name (k0s-owned args/labels are untouched), affinity:null
// drops the required hostname anti-affinity, and the constraints list
// merges on topologyKey. minDomains is set to the wanted value, or to
// explicit null when not wanted: the constraints list merges per
// topologyKey, so an omitted minDomains would SURVIVE from a previous
// DoNotSchedule patch — leaving minDomains on a ScheduleAnyway
// constraint that the API then rejects (the cicd shell override sent
// "minDomains": null for the same reason).
func corednsPatchBody(zoneWhen string, minDomains int) ([]byte, error) {
	zone := map[string]any{
		"maxSkew":            1,
		"topologyKey":        "topology.kubernetes.io/zone",
		"whenUnsatisfiable":  zoneWhen,
		"nodeTaintsPolicy":   "Honor",
		"nodeAffinityPolicy": "Honor",
		"labelSelector":      map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
	}
	if corednsMinDomainsWanted(zoneWhen, minDomains) {
		zone["minDomains"] = minDomains
	} else {
		zone["minDomains"] = nil // explicit null — deletes a stale value
	}
	return json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"affinity": nil,
					"containers": []any{map[string]any{
						"name":           "coredns",
						"livenessProbe":  map[string]any{"timeoutSeconds": 5},
						"readinessProbe": map[string]any{"timeoutSeconds": 5},
						"resources": map[string]any{
							"requests": map[string]any{"cpu": "25m", "memory": "64Mi"},
							"limits":   map[string]any{"cpu": "300m", "memory": "256Mi"},
						},
					}},
					"topologySpreadConstraints": []any{
						zone,
						map[string]any{
							"maxSkew":            1,
							"topologyKey":        "kubernetes.io/hostname",
							"whenUnsatisfiable":  "ScheduleAnyway",
							"nodeTaintsPolicy":   "Honor",
							"nodeAffinityPolicy": "Honor",
							"labelSelector":      map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
						},
					},
				},
			},
		},
	})
}
