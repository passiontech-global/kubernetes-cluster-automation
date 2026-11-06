// spawn.go — Spawn runs fn on a supervised child goroutine: own
// derived cancel ctx, in-goroutine panic recovery, and a stop func
// that cancels then waits. The shared machinery the kubelet-feeder
// (workerhygiene) and sd_notify-feeder (controllerhygiene) spawn
// sites used to hand-roll.
package cycle

import (
	"context"
	"sync"
)

// Spawn starts fn on its own goroutine under a ctx derived from ctx
// and returns stop: cancel the child ctx, then block until the
// goroutine exits.
//
// The child gets its OWN cancel rather than sharing the caller's
// ctx so stop() works on EVERY caller exit path — panic unwinding
// included: a bare `defer wg.Wait()` in the caller also runs during
// unwinding, but the child only exits on ctx.Done() and nothing
// cancels the PARENT ctx when the caller panics, so the wait parked
// forever and the agent's recover never fired (the subsystem died
// silently). Cancelling the derived ctx first bounds the wait.
//
// A panic in fn is recovered and logged — the agent's recover only
// wraps Subsystem.Run itself, not goroutines Run spawned, so an
// unrecovered child panic would take the whole daemon down. Spawn
// never restarts the goroutine: a dead child stays dead until the
// caller spawns a replacement (typically the next Run invocation).
//
// The goroutine is running before Spawn returns, so a caller that
// defers stop() immediately tears down a LIVE child on every exit —
// including a panic in the very next statement. stop is idempotent
// and safe to call more than once. Callers that want the child to
// outlive a single Run (a feeder that must keep working through the
// supervisor's panic-restart backoff) simply never call stop — the
// child then exits when ctx does.
func Spawn(ctx context.Context, name string, fn func(context.Context)) (stop func()) {
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// Registration order is load-bearing (defers run LIFO):
		// the recover is registered LAST so it runs FIRST on
		// unwind — the panic is logged and swallowed BEFORE
		// cancel and wg.Done release a waiting stop(), which then
		// observes a fully unwound child.
		defer wg.Done()
		// Release the child ctx the moment the goroutine exits —
		// fn may have spawned ctx-children (CommandContext execs)
		// that would otherwise live on until the parent dies.
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				logger().Error(name+" panicked — spawned goroutine "+
					"exits, not restarted", "panic", r)
			}
		}()
		fn(cctx)
	}()
	return func() {
		cancel()
		wg.Wait()
	}
}
