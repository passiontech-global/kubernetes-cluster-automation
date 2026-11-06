// supervisor.go — the per-subsystem restart supervisor: one
// goroutine per configured Subsystem, each running the panic-
// recovered Run loop under exponential restart backoff until ctx
// is cancelled. Split out of agent.go, which keeps the HTTP
// serving half (listeners, muxes, gracefulShutdown).
package agent

import (
	"context"
	"time"
)

// supervise launches the supervisor goroutine for every configured
// subsystem and returns immediately. Run calls it before binding
// the listeners so subsystem startup never blocks serving — and a
// subsystem that exits instantly still gets its restart backoff
// regardless of server health.
func (a *Agent) supervise(ctx context.Context) {
	for _, sub := range a.cfg.Subsystems {
		go a.superviseSubsystem(ctx, sub)
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
		logger().Error("subsystem exited unexpectedly — restarting",
			"subsystem", sub.Name(), "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}
}
