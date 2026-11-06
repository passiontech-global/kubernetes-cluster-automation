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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/system/pinnedworkload"
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

// onlyKonnectivityDaemonSet is the exact predicate the For() watch
// below installs — a package var so the test exercises the predicate
// directly instead of introspecting controller-runtime internals.
var onlyKonnectivityDaemonSet = pinnedworkload.OnlyNamespacedName("kube-system", "konnectivity-agent")

// Setup reconciles only the konnectivity-agent
// DaemonSet (the informer is already field-scoped to it via the
// manager cache; the predicate is a cheap belt on top).
func Setup(d shared.Deps) error {
	r := &konnectivityPatcher{cs: d.CS}
	// CountReconcile owns the returned-error accounting — one
	// IncError per non-nil Reconcile return; the reconcile body
	// never IncErrors an error it returns.
	return ctrl.NewControllerManagedBy(d.Mgr).
		Named(d.Name).
		For(&appsv1.DaemonSet{}, builder.WithPredicates(onlyKonnectivityDaemonSet)).
		Complete(shared.CountReconcile(d.Name, r.Reconcile))
}

// Reconcile delegates to the shared pinned-DaemonSet skeleton — this
// module only supplies the kube-system/konnectivity-agent identity,
// the drift check, the rollout-settled gate and the static patch.
func (r *konnectivityPatcher) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	return pinnedworkload.DaemonSetSpec{
		CS:         r.cs,
		Namespace:  "kube-system",
		Name:       "konnectivity-agent",
		Container:  "konnectivity-agent",
		NoDriftLog: "requests+priorityClassName already set - nothing to do",
		PatchLog:   "PATCH: requests/priorityClassName drifted — rollout settled, restoring pinned spec",
		Settled:    kube.DaemonSetSettled,
		Drifted:    konnectivityDrifted,
		Patch:      konnectivityPatch,
	}.Reconcile(ctx)
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
