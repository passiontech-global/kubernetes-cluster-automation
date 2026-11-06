// Route guard — the Go port of nebula-route-guard.sh +
// nebula-route-guard.service: an event-driven netlink listener that
// restores the nebula policy-routing state within ~200ms when the
// kernel loses it (systemd-networkd flushing ip rules on interface
// flap, Cilium policy-routing overwrites — the underlay-flap incidents
// of 2026-09 where the 5-minute watchdog scan left the node isolated
// from the mesh for minutes).
//
// The bash guard ran `ip -ts monitor rule route`, pattern-matched
// "*Deleted*" lines mentioning the dev, the pub/marker tables or
// prefs 1400/1490/1500, slept 0.5s (burst debounce) and re-ran
// /etc/nebula/<net>/nebula-up.sh — gated on
// `systemctl is-active nebula@<net>` == "active" so an operator
// stopping the unit wasn't fought. The port subscribes a
// NETLINK_ROUTE socket to RTMGRP_IPV4_ROUTE|RTMGRP_IPV4_RULE directly
// (no forked monitor), debounces the burst, and execs the same
// script through the runMountCmd seam (`nsenter -t 1 -m -n --` —
// the script needs the host mount ns: it shells out to
// iptables/nft/sysctl which only exist on the host and reads host
// files like /etc/systemd/system/k0sworker.service — exactly the
// environment the unit's ExecStartPost gave it).
//
// The socket must live in the HOST network namespace. The DaemonSet
// runs hostNetwork + hostPID and mounts individual hostPaths only —
// there is NO /host/proc mount, so <hostRoot>/proc/1/ns/net is not
// reachable on workers. Instead: hostNetwork makes the pod's own
// netns the host's — /proc/self/ns/net and /proc/1/ns/net are the
// same inode, so the guard binds directly with no setns at all. On a
// non-hostNetwork hostPID pod /proc/1/ns/net is still host init's
// netns → setns into it for the socket creation (a socket keeps the
// netns it was created in). Only when pid-1's entry can't be used at
// all does the guard fall back to a mounted host /proc under
// <hostRoot>/proc/1/ns/net.
//
// Only DELETE events trigger a restore: RTM_NEWROUTE/RTM_NEWRULE
// belong to the converge's own writers (hostconfig's nebulaRouting,
// the unit's ExecStartPost, module 12) — reacting to adds would just
// re-run the script on every converged change. Deletes are also
// self-limiting: nebula-up.sh is idempotent, so the DEL events its
// own cleanup emits drain to silence once the state is converged.
//
// Only deletes that name the NEBULA dataplane count. The bash guard
// matched the pub/marker tables and prefs 1400/1490/1500 by NAME in
// `ip monitor` text; netlink carries only numbers, but every number
// is a nebula-up.sh constant ($PUB/$MARK, the pref literals) plus one
// sysfs read (the dev's ifindex) — no /etc/iproute2/rt_tables needed.
// The scan decodes each nlmsg: DELROUTE on a nebula table or with
// RTA_OIF == <NebulaDev>, DELRULE at a nebula pref. Everything else —
// the Cilium/Calico pod-route churn that fired ~400 spurious
// restores/day on the cicd workers — is skipped. Decode is FAIL-OPEN:
// a message too torn to classify still counts, because a missed real
// delete strands the node off-mesh for minutes while a spurious
// trigger costs one idempotent script run.
//
// On top of the burst debounce, restores stay capped to one per
// routeGuardMinRestore — the backstop for a sustained RELEVANT
// delete flood: a fire inside the window is re-armed for the
// window's end rather than dropped, so the trailing edge of a flap
// still lands exactly one restore.
//
// With no nebula-up.sh on the host (plain workers) or an inactive
// unit the guard is a no-op — the socket isn't even bound until the
// script exists (polled). Socket errors reopen after 2s, matching the
// outer `while true; ip monitor; sleep 2` resilience, and a bind that
// keeps failing still runs the gated restore (rate-capped) — bash ran
// restore unconditionally at service start, which also covers rules
// lost while the guard can't watch.
package nethealth

import (
	"context"
	"fmt"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/routewatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

const (
	checkRouteGuard = "route-guard"

	// routeGuardDebounce collapses an interface-flap burst (dozens of
	// delete events) into one restore — tighter than the bash
	// `sleep 0.5` since decode costs microseconds, not a fork.
	routeGuardDebounce = 200 * time.Millisecond
	// routeGuardMinRestore caps restore execs under a sustained
	// delete-event flood (Cilium pod-route churn): at most one
	// nebula-up.sh run per window no matter how many bursts arrive.
	routeGuardMinRestore = 2 * time.Second
	// routeGuardRetry is the socket reopen backoff — bash `sleep 2`.
	routeGuardRetry = 2 * time.Second
	// routeGuardPoll re-checks for nebula-up.sh while absent — plain
	// workers without nebula never bind the netlink socket.
	routeGuardPoll = 30 * time.Second
	// routeGuardErrEvery re-logs a persistent bind failure every Nth
	// error (~1min at the 2s retry) — a dead guard must not go
	// silent after the first log line. The same first-plus-every-Nth
	// throttle covers the ENOBUFS warn below: a flooded receive
	// queue must stay visible without one log line per dropped read.
	routeGuardErrEvery = 30
	// routeGuardRespawnBackoff rate-limits guard respawns after an
	// exit: a guard that dies instantly on every spawn (e.g. a
	// deterministic panic) must not spin the spawn path.
	routeGuardRespawnBackoff = 30 * time.Second
)

// --- the guard loop ---
//
// Split by concern: routeguard_filter.go owns the delete-event
// decode, routeguard_monitor.go the bound-socket read + debounce,
// routeguard_restore.go the gated nebula-up.sh re-run. Below are the
// shared helpers, the single-flight spawn and the outer lifecycle.

// watchdogConf returns the current conf race-safely: Cycle() rewrites
// n.cfg.Watchdog only when WatchdogSrc is set, and in that case this
// reads through the (mutexed) reloader instead of the field.
func (n *NetHealth) watchdogConf() *watchdogconf.Config {
	if n.cfg.WatchdogSrc != nil {
		return n.cfg.WatchdogSrc.Get()
	}
	return n.cfg.Watchdog
}

// sleepCtx sleeps d or returns false on ctx cancel.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// spawnRouteGuard starts the route guard unless one is already
// running. The CompareAndSwap preserves the old sync.Once "don't
// stack" guarantee — a second guard would double-bind the netlink
// socket and double-restore — while clearing the flag on exit lets a
// dead guard be re-armed by the next Run restart or tick instead of
// staying dead forever (route events would go unmonitored). A panic
// is recovered and logged: a defect in the guard must not crash the
// whole daemon, and clearing the flag re-arms the next spawn. A
// short backoff after each exit keeps a crash-looping guard from
// spawn-storming.
func (n *NetHealth) spawnRouteGuard(ctx context.Context) {
	// W10-NM4: the MTU-blackhole prober shares this spawn point —
	// Run calls spawnRouteGuard every tick, so a dead prober
	// re-arms exactly like the guard itself. Single-flight inside.
	n.spawnMTUProber(ctx)
	if last := n.routeGuardLastExit.Load(); last != 0 &&
		time.Since(time.Unix(0, last)) < routeGuardRespawnBackoff {
		return
	}
	if !n.routeGuardRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger().Error("route-guard: guard panicked — exiting, "+
					"respawn allowed after backoff",
					"panic", r)
			}
			n.routeGuardLastExit.Store(time.Now().UnixNano())
			n.routeGuardRunning.Store(false)
		}()
		n.routeGuard(ctx)
	}()
}

// routeGuard is the outer lifecycle: poll for nebula-up.sh, bind the
// netlink socket, monitor, reopen on read error — the bash outer
// `while true; ip monitor; sleep 2` loop. Spawned via
// spawnRouteGuard — single-flight while alive, re-arms after exit.
func (n *NetHealth) routeGuard(ctx context.Context) {
	open := n.cfg.openRouteSocket
	if open == nil {
		hostRoot := n.cfg.HostRoot
		open = func() (int, error) { return routewatch.Bind(hostRoot) }
	}
	debounce := n.cfg.routeDebounce
	if debounce <= 0 {
		debounce = routeGuardDebounce
	}
	minRestore := n.cfg.routeMinRestore
	if minRestore <= 0 {
		minRestore = routeGuardMinRestore
	}
	openFails := 0
	var lastFailRestore time.Time
	for {
		if !n.nebulaUpExists(n.watchdogConf()) {
			// No nebula-up.sh (plain worker / nebula not converged):
			// nothing to restore — don't even bind the socket.
			if !sleepCtx(ctx, routeGuardPoll) {
				return
			}
			continue
		}
		fd, err := open()
		if err != nil {
			openFails++
			n.cycles.WithLabelValues(checkRouteGuard, "open_error").Inc()
			// Log the first failure, then every Nth — a permanently
			// dead guard stays visible instead of logging once and
			// going silent.
			if openFails == 1 || openFails%routeGuardErrEvery == 0 {
				n.state.AppendLog(fmt.Sprintf(
					"route-guard: netlink socket failed (x%d): %v (retrying)",
					openFails, err))
			}
			// bash ran restore unconditionally at service start —
			// a bind that never succeeds must still recover rules
			// lost while the guard is down (the script + is-active
			// gates apply inside; capped to one exec per
			// minRestore so a hard-down socket can't exec-storm).
			if time.Since(lastFailRestore) >= minRestore {
				lastFailRestore = time.Now()
				n.restoreRouteGuard(ctx)
			}
			if !sleepCtx(ctx, routeGuardRetry) {
				return
			}
			continue
		}
		openFails = 0
		n.routeGuardRead(ctx, fd, debounce, minRestore)
		if ctx.Err() != nil {
			return
		}
		if !sleepCtx(ctx, routeGuardRetry) {
			return
		}
	}
}

// trimRunErr clips captured output for the log line.
func trimRunErr(out string) string {
	const max = 200
	if len(out) > max {
		out = out[:max]
	}
	for len(out) > 0 && (out[len(out)-1] == '\n' || out[len(out)-1] == ' ') {
		out = out[:len(out)-1]
	}
	return out
}
