// periodic.go — the manager.Runnable that replaces a shell-operator
// `schedule:` binding (Periodic/AddPeriodic) plus the fixed-key watch
// fan-in (FixedSweepRequest/SweepRequests) the full-cluster sweep
// reconcilers use to collapse every watched object into one
// workqueue key.
package shared

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// periodic — replaces a shell-operator `schedule:` binding.
// ---------------------------------------------------------------------------

// Periodic replaces a shell-operator `schedule:` binding — a
// manager.Runnable that ticks fn on interval. Start owns run-level
// error accounting: every non-nil fn return IncErrors p.Name exactly
// once, so fn must NOT IncError errors it returns (double-count) —
// only tolerated sub-operation failures that the run absorbs (log +
// continue, nil return) may IncError from inside fn.
type Periodic struct {
	Name       string
	Interval   time.Duration
	RunTimeout time.Duration
	// NextInterval, when non-nil, switches Start from a fixed NewTicker
	// to an adaptive timer that re-computes the next wait after each
	// runOnce call (receiving the previous interval).
	NextInterval func(prev time.Duration) time.Duration
	Fn           func(ctx context.Context) error
	Log          logr.Logger
}

func (p *Periodic) Start(ctx context.Context) error {
	// A non-positive interval would panic in rand.N / time.NewTicker.
	// AddPeriodic validates at registration, but a Periodic built by
	// hand must still fail here — as a runnable error that stops the
	// manager cleanly, not a panic inside a goroutine that
	// crash-loops the pod.
	if p.Interval <= 0 {
		return fmt.Errorf("periodic %q: interval must be > 0, got %s",
			p.Name, p.Interval)
	}
	// Inject the named logger into the ctx fn sees: modules log via
	// logf.FromContext(ctx), which on the raw manager ctx returns the
	// UNNAMED root logger — every run log line would lack the
	// "logger":"<queue>" field reconcilers get for free. A Periodic
	// built by hand (not via AddPeriodic) may carry a zero-value Log;
	// fall back to naming whatever the ctx already has so the run log
	// and the error log below stay named rather than silently
	// discarding.
	log := p.Log
	if log.GetSink() == nil {
		log = logf.FromContext(ctx).WithName(p.Name)
	}
	runCtx := logf.IntoContext(ctx, log)
	// De-phase the sweep modules: every AddPeriodic caller begins at
	// the same startup moment, so identical NewTicker intervals would
	// fire all modules on the same wall-clock minute — a thundering
	// herd of LIST calls (heap burst) at every common multiple of
	// 5/10/15/30/60m. A one-shot random phase offset uniform in
	// [0, interval) spreads them; the first run then lands in
	// [0, interval) — running immediately after the offset, not
	// waiting out a full extra ticker interval (which used to push
	// the first scan to [interval, 2*interval) and double the blind
	// window a fresh pod rollout sits in). ctx is honored so
	// shutdown is never delayed.
	timer := time.NewTimer(rand.N(p.Interval))
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil
	case <-timer.C:
	}
	if err := p.runOnce(runCtx); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "periodic run failed")
	}
	if p.NextInterval != nil {
		cur := p.Interval
		for {
			cur = p.NextInterval(cur)
			if cur <= 0 {
				cur = p.Interval
			}
			waitTimer := time.NewTimer(cur)
			select {
			case <-ctx.Done():
				waitTimer.Stop()
				return nil
			case <-waitTimer.C:
			}
			if err := p.runOnce(runCtx); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "periodic run failed")
			}
		}
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.runOnce(runCtx); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "periodic run failed")
			}
		}
	}
}

// runOnce invokes Fn once, converting a panic into a plain run error
// so the tick loop treats it exactly like a returned error. The
// choice is deliberate — panic → run error + continue, never
// propagate: controller-runtime does not recover Runnable panics, so
// an unrecovered panic in one module's Fn would take down the whole
// 32-module operator process — a single module's bug crash-looping
// the entire fleet. Folding the panic into the error path keeps the
// ticker alive while the failure still surfaces where ops looks for
// it: IncError bumps shell_operator_hook_run_errors_total{queue} and
// the "periodic run failed" line logs the recovered value under the
// module's named logger. No stack is captured — the named logger +
// queue counter already attribute the failure to the module, which
// is all the run-level contract needs.
func (p *Periodic) runOnce(ctx context.Context) (err error) {
	if p.RunTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.RunTimeout)
		defer cancel()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic in periodic run: %v", recovered)
		}
	}()
	return p.Fn(ctx)
}

// AddPeriodic registers fn to run every interval (equivalent to the
// old crontab entry). name is the legacy queue name for metrics
// compat. interval must be >= 1s: a non-positive interval (e.g. an
// env-derived *_INTERVAL knob set to "0s") would panic time.NewTicker
// inside the runnable, and a sub-second interval would hot-loop the
// sweep — returning an error here instead lets setupModules abort
// boot with the module name attached.
func AddPeriodic(mgr manager.Manager, name string, interval time.Duration, fn func(ctx context.Context) error) error {
	if interval < time.Second {
		return fmt.Errorf("periodic %q: interval must be >= 1s, got %s",
			name, interval)
	}
	return mgr.Add(&Periodic{
		Name:     name,
		Interval: interval,
		Fn:       fn,
		Log:      mgr.GetLogger().WithName(name),
	})
}

// ---------------------------------------------------------------------------
// Fixed-key watch fan-in — for full-cluster sweep reconcilers.
// ---------------------------------------------------------------------------

// FixedSweepRequest builds the single reconcile.Request for key.
func FixedSweepRequest(key string) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: key}}}
}

// SweepRequests returns a handler.MapFunc that collapses every watched
// object to one fixed workqueue key. The sweep modules ignore
// reconcile.Request.Name entirely (a trigger only says "go sweep the
// cluster"), so per-node For() keys fanned one informer sync into N
// queued requests AND N independent RequeueAfter timers — every timer
// re-running the same cluster-wide Nodes().List. One fixed key lets
// the workqueue set-collapse the duplicate enqueues and leaves a
// single RequeueAfter timer: 1 sweep per interval regardless of the
// node count.
func SweepRequests(key string) handler.MapFunc {
	return func(context.Context, client.Object) []reconcile.Request {
		return FixedSweepRequest(key)
	}
}

// NodeUpdatePredicate returns a Node watch predicate that always fires on
// Create, Delete, and Generic events, and on Update events only when changed
// returns true for the old/new Node pair. When an Update event carries missing
// or non-Node objects, it returns fallbackOnMissing.
func NodeUpdatePredicate(fallbackOnMissing bool, changed func(oldNode, newNode *corev1.Node) bool) predicate.Funcs {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldN, ok1 := e.ObjectOld.(*corev1.Node)
			newN, ok2 := e.ObjectNew.(*corev1.Node)
			if !ok1 || !ok2 || oldN == nil || newN == nil {
				return fallbackOnMissing
			}
			return changed(oldN, newN)
		},
	}
}
