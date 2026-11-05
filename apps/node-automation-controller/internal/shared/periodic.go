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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
	Name     string
	Interval time.Duration
	Fn       func(ctx context.Context) error
	Log      logr.Logger
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
	// [0, interval) spreads them; the first run lands in
	// [interval, 2*interval), acceptable for crontab-equivalent
	// sweeps. ctx is honored so shutdown is never delayed.
	timer := time.NewTimer(rand.N(p.Interval))
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil
	case <-timer.C:
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.Fn(runCtx); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "periodic run failed")
			}
		}
	}
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
