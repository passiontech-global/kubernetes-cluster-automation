// reconcile.go — the watch/reconcile half of the run-error
// accounting contract: Periodic.Start owns it for schedule modules
// (see periodic.go), CountReconcile owns it for event-driven sweep
// reconcilers. Watch modules have no run loop to hang the ownership
// on — the builder hands the workqueue straight to Reconcile — so
// the wrapper lives at the Complete() call instead.
package shared

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ReconcileFunc is the reconcile.Reconciler shape the sweep
// reconcilers implement — a plain func so the counting wrapper can
// adapt it without an interface method on the module struct.
type ReconcileFunc func(ctx context.Context, req reconcile.Request) (ctrl.Result, error)

// countedReconciler binds fn to the queue name Reconcile needs —
// the two halves of the IncError contract builder.Complete cannot
// pass separately.
type countedReconciler struct {
	queue string
	fn    ReconcileFunc
}

// Reconcile runs fn and owns the returned-error accounting exactly
// the way Periodic.Start does: one IncError per non-nil error
// return.
func (r countedReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	res, err := r.fn(ctx, req)
	if err != nil {
		metrics.IncError(r.queue)
	}
	return res, err
}

// CountReconcile adapts fn into reconcile.Reconciler with the same
// run-error accounting Periodic.Start gives periodic modules: every
// non-nil error return IncErrors queue exactly once, so the
// reconciler's error paths shrink to bare `return ctrl.Result{},
// err` — IncError inside fn stays reserved for tolerated
// sub-failures (log+continue), never for returned errors. Call
// sites read `b.Complete(shared.CountReconcile(d.Name,
// r.reconcile))`.
func CountReconcile(queue string, fn ReconcileFunc) reconcile.Reconciler {
	return countedReconciler{queue: queue, fn: fn}
}
