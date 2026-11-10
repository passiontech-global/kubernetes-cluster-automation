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

const (
	// superviseBackoffInitial is the first restart wait — 5s, the
	// original supervisor constant.
	superviseBackoffInitial = 5 * time.Second
	// superviseBackoffMax caps the exponential ladder — 5m, the
	// breathing room a permanently sick subsystem gets between
	// restart attempts.
	superviseBackoffMax = 5 * time.Minute
)

// superviseHealthyRun reports whether a run that lasted elapsed
// counts as healthy enough to reset the exponential restart ladder
// to its initial backoff. The bar is deliberately ABSOLUTE — a run
// must outlive twice the CURRENT backoff, or 5 minutes flat, to
// count. Measuring "outlived the current backoff" (the original rule)
// let a crash-loop whose runs die just past the backoff reset the
// ladder every round: run 5.1s → backoff was 5s → reset → crash 5.1s
// → reset … the subsystem stayed pinned at a 5s restart cadence
// forever, never climbing toward the 5m cap that buys a sick node
// breathing room.
func superviseHealthyRun(elapsed, backoff time.Duration) bool {
	return elapsed >= backoff*2 || elapsed >= superviseBackoffMax
}

// restartTimer re-arms the reusable backoff timer for the next wait.
// A run that outlived the previous backoff leaves its fired tick
// queued in timer.C — Reset does not drain it, so the select would
// consume the stale tick immediately and restart with zero wait.
// Stop + drain before Reset — the documented Timer.Reset pattern.
func restartTimer(timer *time.Timer, wait time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(wait)
}

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
	// Restart backoff doubles per early exit (5s → 5m cap) so a
	// subsystem that returns instantly can't spam a restart + error
	// log every cycle. The reset to the initial backoff is gated by
	// superviseHealthyRun: only a run that outlived twice the
	// current backoff (or 5 minutes flat) counts as healthy — the
	// original "outlived the current backoff" rule let a crash-loop
	// with 5.1s runs reset the ladder every round and stay pinned
	// at a 5s restart cadence forever.
	backoff := superviseBackoffInitial
	// atMax tracks whether THIS goroutine currently counts toward
	// a.maxBackoffSubs — the /readyz degraded signal (selfheal-alert-coverage). The
	// counter moves only on transitions so concurrent subsystems
	// never double-count.
	atMax := false
	defer func() {
		if atMax {
			a.maxBackoffSubs.Add(-1)
		}
	}()
	// Reusable backoff timer. A Run that outlives the armed wait —
	// the normal healthy case: the timer fires 5s into every run
	// longer than the backoff — leaves the fired tick QUEUED in
	// timer.C. Reset does not drain it (the old "time.After parity"
	// claim below was wrong for Reset: it holds for a fresh
	// time.After channel, not for Timer.Reset), so a bare Reset let
	// the select consume the stale tick instantly and restart with
	// ZERO wait — the whole 5s→5m ladder silently skipped. Every
	// re-arm goes through restartTimer, which stops and drains first.
	timer := time.NewTimer(backoff)
	defer timer.Stop()
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
		if superviseHealthyRun(time.Since(began), backoff) {
			backoff = superviseBackoffInitial
		}
		// selfheal-alert-coverage: a subsystem whose restart penalty sits at the 5m cap
		// is crash-looping hard enough that readiness should report
		// degraded — /healthz stays 200 so kubelet does not restart
		// the pod and kill the subsystems that ARE healthy. The
		// counter flips on transitions only; a healthy run resets
		// backoff to initial and clears the flag on this same pass.
		nowAtMax := backoff >= superviseBackoffMax
		if nowAtMax != atMax {
			if nowAtMax {
				a.maxBackoffSubs.Add(1)
			} else {
				a.maxBackoffSubs.Add(-1)
			}
			atMax = nowAtMax
		}
		// Run returned while ctx is live (panic recovered, or
		// a silent early return) — restart after backoff
		// instead of letting the subsystem die invisibly.
		// Jitter (±15%) desynchronizes subsystems sharing a
		// restart cadence — without it every crash-looping
		// subsystem restarts in lockstep at 5s and again at
		// the same multiple up the exponential ladder, piling
		// all the restart log lines and work into one burst. The
		// jitter is computed in float BEFORE the Duration
		// conversion — time.Duration(rand.Float64()*2-1)
		// truncates [-1,1) to 0, which would null the jitter
		// term entirely.
		wait := backoff + time.Duration((rand.Float64()*2-1)*float64(backoff*3/20))
		logger().Error("subsystem exited unexpectedly — restarting",
			"subsystem", name, "backoff", backoff, "wait", wait)
		restartTimer(timer, wait)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if backoff *= 2; backoff > superviseBackoffMax {
			backoff = superviseBackoffMax
		}
	}
}
