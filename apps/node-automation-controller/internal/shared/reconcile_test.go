package shared

import (
	"context"
	"errors"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ---------------------------------------------------------------------------
// CountReconcile — the watch-side half of the IncError contract.
// ---------------------------------------------------------------------------

// A returned error must IncError the queue exactly once — the whole
// point of the wrapper is that a bare `return ctrl.Result{}, err`
// at a reconcile error path carries the same counting Periodic.Start
// gives periodic runs, so the ~20 hand-rolled `IncError + return`
// pairs can disappear.
func TestCountReconcileErrorIncrementsOnce(t *testing.T) {
	want := errors.New("boom")
	r := CountReconcile("test-counted-err",
		func(context.Context, reconcile.Request) (ctrl.Result, error) {
			return ctrl.Result{}, want
		})

	before := reconcileErrorCount(t, "test-counted-err")
	if _, err := r.Reconcile(ctx, FixedSweepRequest("test")[0]); !errors.Is(err, want) {
		t.Fatalf("Reconcile error = %v, want %v", err, want)
	}
	if got := reconcileErrorCount(t, "test-counted-err"); got != before+1 {
		t.Fatalf("error counter = %v, want %v", got, before+1)
	}
}

// A nil error must not move the counter — and the ctrl.Result
// (Requeue/RequeueAfter, the sweep modules' crontab safety-net)
// must pass through untouched.
func TestCountReconcileSuccessPassesResultThrough(t *testing.T) {
	want := ctrl.Result{Requeue: true, RequeueAfter: 42 * time.Minute}
	r := CountReconcile("test-counted-ok",
		func(context.Context, reconcile.Request) (ctrl.Result, error) {
			return want, nil
		})

	before := reconcileErrorCount(t, "test-counted-ok")
	got, err := r.Reconcile(ctx, FixedSweepRequest("test")[0])
	if err != nil {
		t.Fatalf("Reconcile error = %v, want nil", err)
	}
	if got != want {
		t.Fatalf("Reconcile result = %+v, want %+v", got, want)
	}
	if c := reconcileErrorCount(t, "test-counted-ok"); c != before {
		t.Fatalf("error counter = %v, want %v — a nil return must not IncError",
			c, before)
	}
}
