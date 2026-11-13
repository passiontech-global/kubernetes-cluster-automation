// liveness_test.go — the /healthz liveness contracts behind NHA-2:
// (1) a cycle.Runner beat cannot outlive its loop — Run
// unregisters it on exit, while a loop hung INSIDE fn keeps its
// beat and stays a genuine liveness failure; (2) the supervisor
// renews the whole Liveness registry before every Run attempt, so
// a panic-recovered restart starts from fresh stamps instead of
// inheriting the dead run's age.
package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

func TestRunnerBeatUnregisteredOnLoopExit(t *testing.T) {
	l := cycle.NewLiveness()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	hung := make(chan struct{})
	done := make(chan struct{})
	r := cycle.Every("wedged-loop", time.Hour, func(context.Context) {
		close(started)
		<-hung
	})
	go func() {
		r.Run(cycle.WithLiveness(ctx, l))
		close(done)
	}()
	<-started

	// Inside fn the beat is registered with the loop's own budget —
	// a slow or hung cycle must stay judged, never silently exempt.
	if got := len(l.LoopBeats()); got != 1 {
		t.Fatalf("LoopBeats() during run=%d want 1", got)
	}

	// ctx cancelled while the loop is hung INSIDE fn: Run cannot
	// reach the unregister defer, so the beat must REMAIN — a
	// genuinely hung loop is exactly what /healthz exists to catch.
	cancel()
	if got := len(l.LoopBeats()); got != 1 {
		t.Fatalf("LoopBeats() after cancel with fn still hung=%d want 1", got)
	}

	close(hung)
	<-done
	// Exit → beat gone. An orphaned beat keeps its last stamp
	// forever and would hold /healthz at 503 permanently after the
	// staleness budget, getting a healthy agent killed.
	if got := len(l.LoopBeats()); got != 0 {
		t.Fatalf("LoopBeats() after Run exit=%d want 0 — an "+
			"orphaned beat wedges /healthz permanently", got)
	}
}

func TestUnregisterUnknownBeatIsNoop(t *testing.T) {
	l := cycle.NewLiveness()
	beat := l.RegisterLoop("once", time.Minute, time.Minute)
	l.Unregister(beat)
	l.Unregister(beat) // double unregister — race-safe no-op
	l.Unregister(nil)
	if got := l.LoopCount(); got != 0 {
		t.Fatalf("LoopCount()=%d want 0 after unregister", got)
	}
	// The fallback beat survives — bare Heartbeat callers judge on
	// it for the registry's whole lifetime.
	if l.Fallback() == nil {
		t.Fatal("Fallback() must never be nil")
	}
}

func TestSuperviseRenewsLivenessPerRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sub := &earlyReturnSubsystem{ran: make(chan struct{})}
	a := New(Config{Subsystems: []Subsystem{sub}})
	var wg sync.WaitGroup
	a.supervise(ctx, &wg)
	defer func() {
		cancel()
		wg.Wait()
	}()

	waitFor(t, "subBeat registered", func() bool {
		_, ok := a.beats.Load("early-return")
		return ok
	})
	sbv, _ := a.beats.Load("early-return")
	sb := sbv.(*subBeat)

	// Attempt 1: fresh registry stamped at run entry.
	var first *cycle.Liveness
	waitFor(t, "first liveness installed", func() bool {
		first = sb.live.Load()
		return first != nil
	})
	waitFor(t, "first entry stamp", func() bool {
		return first.Fallback().LastProgress.Load() > 0
	})

	// Run returned while ctx is live → restart counted → attempt 2
	// must get a NEW registry. The bug this pins: one registry kept
	// for the supervisor goroutine's whole life means the dead
	// run's stamps age forever — /healthz goes 503 permanently
	// ~15 minutes after ANY recovery and the kubelet/systemd
	// watchdog kills an agent whose loops are fine.
	waitFor(t, "restart counted", func() bool {
		return testutil.ToFloat64(
			a.restarts.WithLabelValues("early-return")) >= 1
	})
	var second *cycle.Liveness
	waitFor(t, "liveness renewed per restart", func() bool {
		second = sb.live.Load()
		return second != nil && second != first
	})

	// The renewed registry carries no dead beats and gets a fresh
	// run-entry stamp on the new attempt.
	waitFor(t, "renewed entry stamp", func() bool {
		return second.Fallback().LastProgress.Load() > 0
	})
	if got := len(second.LoopBeats()); got != 0 {
		t.Fatalf("renewed registry carries %d loop beats want 0", got)
	}
}
