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
	fn       func(context.Context)
}

// Every returns a Runner that calls fn once up front, then on every
// interval tick, until ctx is cancelled. The immediate first call is
// the run-immediately contract every converted loop kept (first sweep
// at pod start, then sleep). interval must be > 0 — a non-positive
// interval panics in time.NewTicker, same as the hand-rolled loops
// this replaces.
func Every(name string, interval time.Duration, fn func(context.Context)) *Runner {
	return &Runner{name: name, interval: interval, fn: fn}
}

// Name identifies the runner for logging.
func (r *Runner) Name() string { return r.name }

// Run blocks until ctx is cancelled: fn runs once before the ticker
// is created, then once per interval. It never returns an error —
// transient failures are the fn's problem (log and retry next tick),
// matching the agent.Subsystem contract.
func (r *Runner) Run(ctx context.Context) {
	r.fn(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.fn(ctx)
		}
	}
}

// Idle blocks until ctx is cancelled — the body for a subsystem that
// is constructed but disabled. Run must NOT return while ctx is live:
// agent.Run restarts a returned Run after a backoff, so a disabled
// subsystem parks here instead of exiting.
func Idle(ctx context.Context) { <-ctx.Done() }
