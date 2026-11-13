// reconcile.go — the watch/reconcile half of the run-error
// accounting contract: Periodic.Start owns it for schedule modules
// (see periodic.go), CountReconcile owns it for event-driven sweep
// reconcilers. Watch modules have no run loop to hang the ownership
// on — the builder hands the workqueue straight to Reconcile — so
// the wrapper lives at the Complete() call instead.
package shared

import (
	"context"
	"fmt"

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
// return. A panic inside fn folds into the same accounting —
// controller-runtime does NOT recover Reconcile panics by default
// (builder.RecoverPanic is opt-in and none of the watch reconcilers
// set it), so one module's nil dereference would take down the
// whole 32-module process. Same posture as Periodic.runOnce: panic →
// plain run error + IncError, never propagate; no stack captured —
// the queue counter + the reconciler-error log already attribute
// the failure. Returning the error (not swallowing it) keeps the
// workqueue's exponential backoff alive, so a panicking reconcile
// retries instead of silently dropping the key.
func (r countedReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res ctrl.Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			metrics.IncError(r.queue)
			res, err = ctrl.Result{}, fmt.Errorf("panic in reconcile: %v", recovered)
		}
	}()
	res, err = r.fn(ctx, req)
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
