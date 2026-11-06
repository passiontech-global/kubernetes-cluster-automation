// routeguard_monitor.go — the bound-socket monitor: a reader
// goroutine turns netlink datagrams into event signals and closes
// done on exit (read error, EOF or fd close), a watcher closes the
// fd on ctx cancel to unblock Read, and the debounce loop collapses
// bursts into one rate-capped restore. done is BROADCAST via
// close() so the reader's exit reaches BOTH the watcher and the
// debounce loop.
package nethealth

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// routeGuardRead monitors fd: a reader goroutine turns datagrams into
// event signals and closes done on exit (read error, EOF or fd
// close), a watcher closes fd on ctx cancel to unblock Read, and the
// debounce loop drives the restore. done is BROADCAST via close() so
// the reader's exit reaches BOTH the watcher and the debounce loop —
// a send-once error channel let whichever select won consume it, and
// the other side then stalled silently forever. Returns on reader
// exit or cancel (the outer loop then reopens after the backoff).
func (n *NetHealth) routeGuardRead(ctx context.Context, fd int,
	debounce, minRestore time.Duration) {
	// The delete filter arms once per socket session: a rebuilt
	// nebula dev (tun recreate) or a watchdog-conf table renumber
	// only re-reads on the next socket reopen. The ifindex read
	// failing is NOT fatal — matching then falls back to
	// tables+prefs.
	filter := n.nebulaRouteFilter()
	events := make(chan struct{}, 16)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeFd := func() { closeOnce.Do(func() { _ = unix.Close(fd) }) }
	defer closeFd()
	go func() {
		// Registered first so it runs LAST on unwind: done and the
		// fd close first so the monitor still unwinds, then the
		// panic is logged and swallowed — a defect in the reader
		// must not crash the whole daemon.
		defer func() {
			if r := recover(); r != nil {
				logger().Error("route-guard: netlink reader panicked — "+
					"monitor exits, socket will reopen",
					"panic", r)
			}
		}()
		defer close(done)
		defer closeFd()
		buf := make([]byte, 64*1024)
		enobufs := 0 // overruns seen on THIS socket — warn throttle
		for {
			nr, err := unix.Read(fd, buf)
			if errors.Is(err, unix.ENOBUFS) {
				enobufs++
				// Receive queue overrun: DEL events were dropped —
				// the silent-loss mode the SO_RCVBUF bump shrinks
				// but can't remove. Count the window as a delete
				// burst so the debounced restore heals whatever
				// was missed instead of pretending all is well;
				// the socket itself is still good. The warn is
				// throttled like the open-fail counter: first
				// overrun + every Nth, so a sustained flood can't
				// emit a line per read while staying visible.
				if enobufs == 1 || enobufs%routeGuardErrEvery == 0 {
					logger().Warn("route-guard: netlink receive queue "+
						"overrun — events lost, forcing a restore",
						"overruns", enobufs)
				}
				select {
				case events <- struct{}{}:
				default:
				}
				continue
			}
			if err != nil || nr == 0 {
				// err: closed/failing fd; nr==0: peer EOF. A close
				// triggered by ctx cancel is the normal shutdown —
				// only unexpected read failures are worth a trail.
				if err != nil && ctx.Err() == nil {
					logger().Debug("route-guard: netlink read failed — "+
						"socket will reopen",
						"error", err)
				}
				return
			}
			if filter.scanDeleteEvents(buf[:nr]) {
				select {
				case events <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger().Error("route-guard: cancel watcher panicked",
					"panic", r)
			}
		}()
		select {
		case <-ctx.Done():
			closeFd() // unblock the Read → reader exits → done closes
		case <-done:
		}
	}()
	// bash parity: restore once up front — the guard must catch rules
	// lost while it was down (boot race), not only fresh deletes.
	n.restoreRouteGuard(ctx)
	routeGuardDebounceLoop(ctx, events, done, debounce, minRestore,
		n.restoreRouteGuard)
}

// routeGuardDebounceLoop collapses event bursts into one restore:
// trailing-edge debounce after the last event, plus a minimum
// interval between restores — the exec-storm cap (Cilium pod-route
// churn emits IPv4 DEL events for minutes at a time and each restore
// runs ~20 subcommands). A fire inside the interval is re-armed for
// the window's end rather than dropped, so the last burst of a flap
// still lands exactly one restore. done (reader exit) aborts the
// monitor.
func routeGuardDebounceLoop(ctx context.Context, events <-chan struct{},
	done <-chan struct{}, debounce, minRestore time.Duration,
	reconcile func(context.Context)) {
	var lastRestore time.Time // zero → the first burst restores at once
	var timer *time.Timer
	var fire <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-events:
			if timer == nil {
				timer = time.NewTimer(debounce)
			} else {
				timer.Reset(debounce)
			}
			fire = timer.C
		case <-fire:
			fire = nil // disarm until the next event/re-arm
			if wait := minRestore - time.Since(lastRestore); wait > 0 {
				timer.Reset(wait)
				fire = timer.C
				continue
			}
			lastRestore = time.Now()
			reconcile(ctx)
		}
	}
}
