// supervisor.go — the per-subsystem restart supervisor: one
// goroutine per configured Subsystem, each running the panic-
// recovered Run loop under exponential restart backoff until ctx
// is cancelled. Split out of agent.go, which keeps the HTTP
// serving half (listeners, muxes, gracefulShutdown).
package agent

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

// supervise launches the supervisor goroutine for every configured
// subsystem and returns immediately. Run calls it before binding
// the listeners so subsystem startup never blocks serving — and a
// subsystem that exits instantly still gets its restart backoff
// regardless of server health. Each goroutine is counted in wg so
// Run can wait for subsystem teardown (deferred state flushes) on
// shutdown instead of abandoning the loops mid-flight.
func (a *Agent) supervise(ctx context.Context, wg *sync.WaitGroup) {
	for _, sub := range a.cfg.Subsystems {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.superviseSubsystem(ctx, sub)
		}()
	}
}

// superviseSubsystem is one subsystem's supervision loop: Run under
// panic recovery, the subUp/restarts metric updates, and the
// 5s→5m exponential restart backoff. It returns only when ctx is
// cancelled — a Run that exits while ctx is live is always treated
// as a crash (panic-recovered or silent early return) and restarted
// after backoff instead of letting the subsystem die invisibly.
func (a *Agent) superviseSubsystem(ctx context.Context, sub Subsystem) {
	name := sub.Name()
	logger().Info("subsystem started", "name", name)
	up := a.subUp.WithLabelValues(name)
	restarts := a.restarts.WithLabelValues(name)
	// Restart backoff doubles per early exit (5s → 5m cap) so
	// a subsystem that returns instantly can't spam a restart
	// + error log every cycle; a run that outlived the
	// current backoff counts as healthy and resets it.
	backoff := 5 * time.Second
	for {
		began := time.Now()
		up.Set(1)
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger().Error("subsystem panicked — restarting",
						"subsystem", name, "panic", r)
				}
			}()
			sub.Run(ctx)
		}()
		up.Set(0)
		if ctx.Err() != nil {
			return
		}
		restarts.Inc()
		if time.Since(began) >= backoff {
			backoff = 5 * time.Second
		}
		// Run returned while ctx is live (panic recovered, or
		// a silent early return) — restart after backoff
		// instead of letting the subsystem die invisibly.
		// Jitter (±15%) desynchronizes subsystems sharing a
		// restart cadence — without it every crash-looping
		// subsystem restarts in lockstep at 5s and again at
		// the same multiple up the exponential ladder, piling
		// all the restart log lines and work into one burst.
		wait := backoff + time.Duration(rand.Float64()*2-1)*(backoff*3/20)
		logger().Error("subsystem exited unexpectedly — restarting",
			"subsystem", name, "backoff", backoff, "wait", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}
}
