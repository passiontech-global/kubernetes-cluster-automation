// group.go — RunAll fans N named loops out on supervised child
// goroutines (the Spawn machinery: own derived cancel + in-goroutine
// panic recovery) and blocks until ctx is cancelled, then waits for
// every child to unwind — the "Run spawns a WaitGroup of tickers"
// shape kinedb and hostconfig hand-rolled.
package cycle

import (
	"context"
	"sync"
)

// Looper is the structural contract RunAll drives — Name() +
// Run(context.Context), the same pair agent.Subsystem declares.
// Declared here rather than imported so platform stays a leaf:
// *Runner satisfies it, and so does every subsystem's Run method.
type Looper interface {
	Name() string
	Run(context.Context)
}

// RunAll starts every loop on its own Spawn-supervised goroutine,
// then parks: it returns when ctx is cancelled — after stop()ing
// (cancel-then-wait) every child — or when EVERY loop has exited.
//
// Blocking on ctx while children are live matches the supervisor
// contract: agent.Run restarts a Run that returns early, so the
// group must not return while any loop could still be working. A
// child that exits while ctx is still live is logged at Warn (Spawn
// already logs a panicking child) and is NOT restarted — re-arming
// dead loops is each subsystem's own single-flight business
// (nethealth's spawnRouteGuard), not the group's. Once the LAST
// child is gone the group has nothing left to park for, so RunAll
// returns early and the supervisor's restart path applies — that is
// also the only way a group whose loops all died gets back up.
func RunAll(ctx context.Context, loops ...Looper) {
	var wg sync.WaitGroup
	stops := make([]func(), 0, len(loops))
	for _, l := range loops {
		wg.Add(1)
		stops = append(stops, Spawn(ctx, l.Name(),
			func(cctx context.Context) {
				defer wg.Done()
				l.Run(cctx)
				// A clean return while the parent ctx is still
				// live is as dead as a panic — Spawn's recover
				// only reports the panicking half.
				if ctx.Err() == nil {
					logger().Warn("loop exited while ctx live — "+
						"stays dead until RunAll returns",
						"loop", l.Name())
				}
			}))
	}
	allDone := make(chan struct{})
	go func() { wg.Wait(); close(allDone) }()
	select {
	case <-ctx.Done():
	case <-allDone:
	}
	for _, stop := range stops {
		stop()
	}
}
