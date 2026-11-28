// periodic.go — the manager.Runnable that replaces a shell-operator
// `schedule:` binding (Periodic/AddPeriodic) plus the fixed-key watch
// fan-in (FixedSweepRequest/SweepRequests) the full-cluster sweep
// reconcilers use to collapse every watched object into one
// workqueue key.
package shared

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"runtime/debug"
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
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

const skipInitialJitterEnv = "NODE_AUTOMATION_TEST_NO_INITIAL_JITTER"

// ---------------------------------------------------------------------------
// periodic — replaces a shell-operator `schedule:` binding.
// ---------------------------------------------------------------------------

// DefaultLivenessFloor is the minimum staleness budget for any
// active Periodic loop — keeps short-interval loops from tripping
// /healthz during normal apiserver jitter.
const DefaultLivenessFloor = timex.DefaultLivenessFloor

type livenessCtxKey struct{}

// Liveness adapts libs/hostkit/timex.Liveness to controller-runtime's
// healthz.Checker signature so /healthz checks detect wedged run loops
// without false-failing on standby replicas or NTP wall-clock jumps.
type Liveness struct {
	timex.Liveness
}

// NewLiveness constructs a Liveness tracker anchored to the
// monotonic clock at creation time with DefaultLivenessFloor enforced.
func NewLiveness() *Liveness {
	return &Liveness{
		Liveness: timex.Liveness{Floor: DefaultLivenessFloor},
	}
}

// WithLiveness attaches l to ctx so every Periodic loop started under
// ctx registers and heartbeats automatically.
func WithLiveness(ctx context.Context, l *Liveness) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, livenessCtxKey{}, l)
}

// LivenessFromContext returns the Liveness tracker attached to ctx,
// or nil if none was installed.
func LivenessFromContext(ctx context.Context) *Liveness {
	if ctx == nil {
		return nil
	}
	l, _ := ctx.Value(livenessCtxKey{}).(*Liveness)
	return l
}

func (l *Liveness) floor() time.Duration {
	if l != nil && l.Floor > 0 {
		return l.Floor
	}
	return DefaultLivenessFloor
}

// Check implements controller-runtime's healthz.Checker signature:
// returns nil when no loops are registered (standby / pre-start) or
// every active loop has progressed within its staleness budget.
func (l *Liveness) Check(_ *http.Request) error {
	if l == nil {
		return nil
	}
	return l.Liveness.Check()
}

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
	// Liveness overrides the context-injected Liveness tracker when
	// non-nil (useful for isolated unit tests).
	Liveness *Liveness
	// SkipInitialJitter disables the startup phase-offset wait before
	// the first run; set by AddPeriodicWithTimeout when
	// NODE_AUTOMATION_TEST_NO_INITIAL_JITTER=true for E2E subprocesses.
	SkipInitialJitter bool
}

func (p *Periodic) effectiveTimeout() time.Duration {
	if p.RunTimeout > 0 {
		return p.RunTimeout
	}
	return max(2*p.Interval, 3*time.Minute)
}

func (p *Periodic) livenessBudget(wait, floor time.Duration) time.Duration {
	span := max(p.Interval, wait)
	return max(2*span+p.effectiveTimeout(), floor)
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

	liveness := p.Liveness
	if liveness == nil {
		liveness = LivenessFromContext(ctx)
	}
	var beat *timex.Beat
	if liveness != nil {
		beat = liveness.Register(p.Name, p.livenessBudget(p.Interval, liveness.floor()))
		defer liveness.Unregister(beat)
	}
	stamp := func() {
		beat.Beat()
	}

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
	// shutdown is never delayed. The phase offset is capped at
	// 45s: a 60m interval would otherwise park the first run up
	// to an hour out, and the ±5% per-tick jitter below keeps the
	// modules de-phased after that first run anyway.
	if !p.SkipInitialJitter {
		initialJitter := p.Interval
		if cap := 45 * time.Second; initialJitter > cap {
			initialJitter = cap
		}
		timer := time.NewTimer(rand.N(initialJitter))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	p.invokeOnce(runCtx, log)
	stamp()
	if p.NextInterval != nil {
		cur := p.Interval
		for {
			cur = p.NextInterval(cur)
			if cur <= 0 {
				cur = p.Interval
			}
			if beat != nil {
				beat.SetStaleAfter(p.livenessBudget(cur, liveness.floor()))
			}
			waitTimer := time.NewTimer(cur)
			select {
			case <-ctx.Done():
				waitTimer.Stop()
				return nil
			case <-waitTimer.C:
			}
			p.invokeOnce(runCtx, log)
			stamp()
		}
	}
	// ±5% per-tick jitter: modules sharing an interval (the 5/10/
	// 15/30/60m sweep family) would otherwise re-align on every
	// common multiple forever — the initial phase offset only
	// spreads the FIRST firing. A random wait in [0.95,1.05)
	// times the interval walks each module's phase independently
	// so the herd never re-forms.
	for {
		jitter := time.Duration(rand.Int64N(int64(p.Interval)/10)) -
			p.Interval/20
		wait := p.Interval + jitter
		if wait < time.Second {
			wait = time.Second
		}
		if beat != nil && wait > p.Interval {
			beat.SetStaleAfter(p.livenessBudget(wait, liveness.floor()))
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		p.invokeOnce(runCtx, log)
		stamp()
	}
}

type panicError struct {
	val   any
	stack string
}

func (e *panicError) Error() string {
	return fmt.Sprintf("panic in periodic run: %v", e.val)
}

func (p *Periodic) invokeOnce(ctx context.Context, log logr.Logger) {
	if err := p.runOnce(ctx); err != nil {
		metrics.IncError(p.Name)
		var pe *panicError
		if errors.As(err, &pe) {
			log.Error(err, "periodic run failed", "stack", pe.stack)
		} else {
			log.Error(err, "periodic run failed")
		}
	}
}

// runOnce invokes Fn once, converting a panic into a plain run error
// (capturing debug.Stack) so the tick loop treats it exactly like a
// returned error. The choice is deliberate — panic → run error +
// continue, never propagate: controller-runtime does not recover
// Runnable panics, so an unrecovered panic in one module's Fn would
// take down the whole 32-module operator process — a single module's
// bug crash-looping the entire fleet. Folding the panic into the
// error path keeps the ticker alive while the failure still surfaces
// where ops looks for it: IncError bumps
// shell_operator_hook_run_errors_total{queue} and the "periodic run
// failed" line logs the recovered value plus stack under the
// module's named logger.
func (p *Periodic) runOnce(ctx context.Context) (err error) {
	// Default run budget for modules that declare none:
	// max(2*Interval, 3m) — a wedged sweep must not park its
	// goroutine forever, and a run legitimately longer than its
	// own period is already a bug the timeout should surface.
	timeout := p.effectiveTimeout()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &panicError{
				val:   recovered,
				stack: string(debug.Stack()),
			}
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
	return AddPeriodicWithTimeout(mgr, name, interval, 0, fn)
}

// AddPeriodicWithTimeout is AddPeriodic with an explicit per-run
// RunTimeout override (<= 0 uses Periodic's default
// max(2*Interval, 3m)).
func AddPeriodicWithTimeout(mgr manager.Manager, name string, interval, runTimeout time.Duration, fn func(ctx context.Context) error) error {
	if interval < time.Second {
		return fmt.Errorf("periodic %q: interval must be >= 1s, got %s",
			name, interval)
	}
	return mgr.Add(&Periodic{
		Name:              name,
		Interval:          interval,
		RunTimeout:        runTimeout,
		Fn:                fn,
		Log:               mgr.GetLogger().WithName(name),
		SkipInitialJitter: envx.Gate(skipInitialJitterEnv, false),
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

// RequeueAfter returns d jittered by ±10% — the watch-reconciler
// twin of Periodic's per-tick jitter: reconcilers sharing a requeue
// cadence (the pinned-workload/taint-reaper family) would otherwise
// re-align their safety-net sweeps on every common multiple and
// re-form the same API burst the jitter exists to break up. The
// result stays inside [0.9d, 1.1d) — callers keep their declared
// cadence as the mean.
func RequeueAfter(d time.Duration) time.Duration {
	if d <= 0 {
		// Int64N panics on a non-positive bound — a zero/negative
		// cadence has no jitter to add anyway.
		return d
	}
	jitter := time.Duration(rand.Int64N(int64(d)/5)) - d/10
	return d + jitter
}
