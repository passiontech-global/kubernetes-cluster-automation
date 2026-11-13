// Package cycle is the shared periodic-runner every agent subsystem
// used to hand-roll: invoke fn immediately, then every interval,
// until ctx is cancelled.
//
// Runner deliberately does NOT import internal/agent — platform
// packages must stay a leaf. Its Name/Run pair structurally
// satisfies agent.Subsystem, so a *Runner (or a subsystem delegating
// to one) can be appended to agent.Config.Subsystems as-is.
package cycle

import (
	"context"
	"time"
)

// Runner drives fn on a fixed cadence. Construct via Every.
type Runner struct {
	name     string
	interval time.Duration
	budget   time.Duration
	fn       func(context.Context)
}

// Every returns a Runner that calls fn once up front, then on every
// interval tick, until ctx is cancelled. The immediate first call is
// the run-immediately contract every converted loop kept (first sweep
// at pod start, then sleep). interval must be > 0 — a non-positive
// interval panics in time.NewTicker, same as the hand-rolled loops
// this replaces.
func Every(name string, interval time.Duration, fn func(context.Context)) *Runner {
	return &Runner{name: name, interval: interval,
		budget: DefaultCycleBudget, fn: fn}
}

// EverySafe is Every with per-tick panic recovery — the safeCycle
// shape kinedb hand-rolled: a panicking fn is recovered and logged,
// then the loop keeps ticking instead of the goroutine unwinding
// past the ticker. Prefer plain Every when a defect SHOULD unwind
// Run to the supervisor's recover + restart backoff.
//
// onPanic, when non-nil, runs inside the recover so the caller can
// count the panic in its own metrics (kinedb's
// cycles{loop,"panic"}); nil means the log line alone suffices.
func EverySafe(name string, interval time.Duration,
	fn func(context.Context), onPanic func(name string, recovered any)) *Runner {
	return &Runner{name: name, interval: interval,
		budget: DefaultCycleBudget, fn: func(ctx context.Context) {
			defer func() {
				if r := recover(); r != nil {
					logger().Error(name+" tick panicked — cycle "+
						"skipped, loop keeps ticking", "panic", r)
					if onPanic != nil {
						onPanic(name, r)
					}
				}
			}()
			fn(ctx)
		}}
}

// Name identifies the runner for logging.
func (r *Runner) Name() string { return r.name }

// Run blocks until ctx is cancelled: fn runs once before the ticker
// is created, then once per interval. It never returns an error —
// transient failures are the fn's problem (log and retry next tick),
// matching the agent.Subsystem contract.
//
// Liveness: under an agent-supervised ctx (WithLiveness) the runner
// registers its own Beat with a staleness budget of
// max(3*interval + budget, LivenessFloor) and stamps it at the START
// and END of every run — the start stamp is the startup grace that
// lets a legitimately long first cycle finish, the end stamp keeps
// the cadence honest. The beat is unregistered when Run returns, so
// a restarted loop's replacement beat starts fresh instead of
// inheriting the dead run's last stamp. A hung fn stops stamping and
// /healthz reports 503 once ITS OWN budget is exceeded (a panicking
// fn under EverySafe is recovered inside fn, so the stamp still
// lands: a crash-looping cycle is alive, a wedged one is not).
// Outside a supervised ctx the beat is nil and stamping is a no-op.
func (r *Runner) Run(ctx context.Context) {
	var beat *Beat
	if l := LivenessFrom(ctx); l != nil {
		beat = l.RegisterLoop(r.name, r.interval, r.budget)
		// The beat must not outlive the loop: Run exits on ctx
		// cancel (shutdown) or — under the supervisor's restart —
		// on a fn panic unwinding past the ticker, and a beat left
		// registered keeps its last stamp forever. Unregistering on
		// the way out keeps exactly the wedged case 503: a loop
		// hung INSIDE fn never reaches this defer.
		defer l.Unregister(beat)
	}
	stampLoop(beat)
	r.fn(ctx)
	stampLoop(beat)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			stampLoop(beat)
			r.fn(ctx)
			stampLoop(beat)
		}
	}
}

// Idle blocks until ctx is cancelled — the body for a subsystem that
// is constructed but disabled. Run must NOT return while ctx is live:
// agent.Run restarts a returned Run after a backoff, so a disabled
// subsystem parks here instead of exiting. The parked loop is alive
// by definition, so Idle exempts the ctx's liveness registry from
// the /healthz staleness check — otherwise the run-entry stamp would
// go stale 15 minutes in and kubelet would kill a perfectly healthy
// agent for doing nothing.
func Idle(ctx context.Context) {
	Exempt(ctx)
	<-ctx.Done()
}
