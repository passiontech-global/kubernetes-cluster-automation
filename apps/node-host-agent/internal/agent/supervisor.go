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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

const (
	// superviseBackoffInitial is the first restart wait — 5s, the
	// original supervisor constant.
	superviseBackoffInitial = 5 * time.Second
	// superviseBackoffMax caps the exponential ladder — 5m, the
	// breathing room a permanently sick subsystem gets between
	// restart attempts.
	superviseBackoffMax = 5 * time.Minute
	// superviseHealthyCap bounds the mid-run healthy threshold —
	// min(2*backoff, this): a run stable this long proves the
	// crash-loop is over even when backoff sits at the 5m cap.
	superviseHealthyCap = superviseBackoffMax
)

// superviseHealthyAfter is the elapsed time after which a RUNNING
// (not yet exited) subsystem counts as healthy: min(2*backoff,
// superviseHealthyCap). It mirrors superviseHealthyRun's post-exit
// bar so the mid-run reset and the exit-path reset agree — a run
// that would reset the ladder on exit resets it as soon as it
// proves stable, without waiting for the exit that may never come.
func superviseHealthyAfter(backoff time.Duration) time.Duration {
	d := backoff * 2
	if d > superviseHealthyCap {
		d = superviseHealthyCap
	}
	return d
}

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

// supervise launches the supervisor goroutine for every configured
// subsystem and returns immediately. Run calls it before binding
// the listeners so subsystem startup never blocks serving — and a
// subsystem that exits instantly still gets its restart backoff
// regardless of server health. Each goroutine is counted in wg so
// Run can wait for subsystem teardown (deferred state flushes) on
// shutdown instead of abandoning the loops mid-flight.
func (a *Agent) supervise(ctx context.Context, wg *sync.WaitGroup) {
	for _, sub := range a.cfg.Subsystems {
		wg.Go(func() {
			a.superviseSubsystem(ctx, sub)
		})
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
	// Liveness registry: /healthz reads per-loop staleness while
	// active is set. The registry is RENEWED at the top of every
	// Run attempt (atomic.Pointer — /healthz reads it
	// concurrently), so a panic-recovered restart never inherits
	// the dead run's stamps: their age would trip the staleness
	// check ~15 minutes after every recovery and get a healthy
	// agent killed. Runner loops additionally unregister their
	// own beats on exit (cycle.Runner.Run); a genuinely hung loop
	// — the one case that never exits — still reports stale.
	sb := &subBeat{}
	a.beats.Store(name, sb)
	defer a.beats.Delete(name)
	// Restart backoff doubles per early exit (5s → 5m cap) so a
	// subsystem that returns instantly can't spam a restart + error
	// log every cycle. The reset to the initial backoff is gated by
	// superviseHealthyRun: only a run that outlived twice the
	// current backoff (or 5 minutes flat) counts as healthy — the
	// original "outlived the current backoff" rule let a crash-loop
	// with 5.1s runs reset the ladder every round and stay pinned
	// at a 5s restart cadence forever.
	backoff := a.backoffInitial
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
	// The backoff timer is allocated LAZILY on the first restart —
	// the common case (a long healthy run) never creates one, and a
	// fresh time.NewTimer per wait has no stale-tick hazard: the
	// fired-tick drain the old reusable timer needed (restartTimer)
	// existed only because Reset does not drain timer.C. A brand-new
	// channel per restart makes the select's <-timer.C unambiguous.
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		began, stopped := runSubsystemAttempt(ctx, name, sub, sb, up,
			superviseHealthyAfter(backoff), func() {
				if atMax {
					a.maxBackoffSubs.Add(-1)
					atMax = false
				}
				backoff = a.backoffInitial
			})
		if stopped {
			return
		}
		restarts.Inc()
		if superviseHealthyRun(time.Since(began), backoff) {
			backoff = a.backoffInitial
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
		wait := jitteredBackoff(backoff)
		logger().Error("subsystem exited unexpectedly — restarting",
			"subsystem", name, "backoff", backoff, "wait", wait)
		timer = time.NewTimer(wait)
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

// runSubsystemAttempt launches one panic-recovered sub.Run attempt with a fresh
// per-run cancel context and liveness registry, returning true when ctx stopped
// it (so the supervisor should exit rather than restart).
func runSubsystemAttempt(
	ctx context.Context,
	name string,
	sub Subsystem,
	sb *subBeat,
	up prometheus.Gauge,
	healthyAfter time.Duration,
	onHealthy func(),
) (began time.Time, stopped bool) {
	began = time.Now()
	// Fresh registry per attempt — the old one dies with the run that exited,
	// stale stamps and all.
	sb.live.Store(cycle.NewLiveness())
	up.Set(1)
	sb.active.Store(true)
	// Each run gets its own cancelable context: sub.Run spawns child goroutines
	// (probers, guards, feeders) that must die with the run — a panic-recovered
	// restart reusing parent ctx would orphan children and keep heartbeating.
	runCtx, runCancel := context.WithCancel(ctx)
	lctx := cycle.WithLiveness(runCtx, sb.live.Load())
	cycle.Heartbeat(lctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				logger().Error("subsystem panicked — restarting",
					"subsystem", name, "panic", r)
			}
		}()
		// Registered last so it runs FIRST on exit — children cancel before
		// done closes and the supervisor starts the next attempt.
		defer runCancel()
		sub.Run(lctx)
	}()
	// Mid-run healthy watch: outliving healthyAfter proves the crash-loop ended
	// — clear /readyz degraded state now rather than waiting for the next exit.
	healthy := time.NewTimer(healthyAfter)
	select {
	case <-done:
		healthy.Stop()
	case <-ctx.Done():
		healthy.Stop()
		<-done
		up.Set(0)
		sb.active.Store(false)
		return began, true
	case <-healthy.C:
		onHealthy()
		<-done
	}
	up.Set(0)
	sb.active.Store(false)
	return began, ctx.Err() != nil
}

// jitteredBackoff adds ±15% jitter in float before converting to Duration so
// crash-looping subsystems sharing a cadence desynchronize.
func jitteredBackoff(backoff time.Duration) time.Duration {
	return backoff + time.Duration((rand.Float64()*2-1)*float64(backoff*3/20))
}
