// konnectivity_patcher.go — port of
// hooks/10-konnectivity-agent-patcher.sh.
//
// Keeps daemonset kube-system/konnectivity-agent at
// resources.requests {cpu:25m, memory:32Mi} (Burstable) +
// priorityClassName system-node-critical — konnectivity is the
// apiserver's kubectl exec/logs path. The DS is owned by the k0s
// stack applier, which reverts the manifest (resources back to {} /
// BestEffort) on every apply event, not just upgrades, so drift comes
// back many times per hour. The watch patches it back in <1s; the 15m
// requeue replaces the old crontab safety net. Never patches while a
// rollout is in flight — that would stack a second rolling restart
// (double flap, "No agent available" on kubectl exec).
package konnectivitypatcher

import (
	"context"
	"fmt"
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
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// Exact patch body from the bash hook — strategic merge lands the
// requests into the existing "konnectivity-agent" container by name.
var konnectivityPatch = []byte(`{"spec":{"template":{"spec":{"priorityClassName":"system-node-critical","containers":[{"name":"konnectivity-agent","resources":{"requests":{"cpu":"25m","memory":"32Mi"}}}]}}}}`)

var (
	konnectivityWantCPU = resource.MustParse("25m")
	konnectivityWantMem = resource.MustParse("32Mi")
)

type konnectivityPatcher struct {
	cs kubernetes.Interface
}

// Setup reconciles only the konnectivity-agent
// DaemonSet (the informer is already field-scoped to it via the
// manager cache; the predicate is a cheap belt on top).
func Setup(mgr ctrl.Manager, cs kubernetes.Interface) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("konnectivity-patcher").
		For(&appsv1.DaemonSet{}, builder.WithPredicates(
			predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetNamespace() == "kube-system" &&
					o.GetName() == "konnectivity-agent"
			}))).
		Complete(&konnectivityPatcher{cs: cs})
}

func (r *konnectivityPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	res := ctrl.Result{RequeueAfter: 15 * time.Minute}

	ds, err := r.cs.AppsV1().DaemonSets("kube-system").
		Get(ctx, "konnectivity-agent", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// DS may not exist (cluster without konnectivity)
		log.Info("SKIP: daemonset not found", "daemonset", "kube-system/konnectivity-agent")
		return res, nil
	}
	if err != nil {
		metrics.IncError("konnectivity-patcher")
		return ctrl.Result{}, fmt.Errorf("get daemonset kube-system/konnectivity-agent: %w", err)
	}

	if !konnectivityDrifted(ds) {
		log.Info("requests+priorityClassName already set - nothing to do",
			"daemonset", "kube-system/konnectivity-agent")
		return res, nil
	}
	if !shared.DaemonSetSettled(ds) {
		log.Info("SKIP: drifted but rollout in progress",
			"daemonset", "kube-system/konnectivity-agent",
			"generation", ds.Generation,
			"observedGeneration", ds.Status.ObservedGeneration,
			"updated", ds.Status.UpdatedNumberScheduled,
			"ready", ds.Status.NumberReady,
			"desired", ds.Status.DesiredNumberScheduled)
		return res, nil
	}

	log.Info("PATCH: requests/priorityClassName drifted — rollout settled, restoring pinned spec",
		"daemonset", "kube-system/konnectivity-agent")
	if _, err := r.cs.AppsV1().DaemonSets("kube-system").Patch(ctx,
		"konnectivity-agent", types.StrategicMergePatchType,
		konnectivityPatch, metav1.PatchOptions{}); err != nil {
		metrics.IncError("konnectivity-patcher")
		return ctrl.Result{}, fmt.Errorf("patch daemonset kube-system/konnectivity-agent: %w", err)
	}
	return res, nil
}

// konnectivityDrifted reports whether the DS lacks the pinned
// requests/priorityClassName. A missing container counts as drifted
// (the bash jsonpath probe yields an empty $cur then too).
func konnectivityDrifted(ds *appsv1.DaemonSet) bool {
	if ds.Spec.Template.Spec.PriorityClassName != "system-node-critical" {
		return true
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "konnectivity-agent" {
			cpu := c.Resources.Requests[corev1.ResourceCPU]
			mem := c.Resources.Requests[corev1.ResourceMemory]
			return cpu.Cmp(konnectivityWantCPU) != 0 ||
				mem.Cmp(konnectivityWantMem) != 0
		}
	}
	return true
}
