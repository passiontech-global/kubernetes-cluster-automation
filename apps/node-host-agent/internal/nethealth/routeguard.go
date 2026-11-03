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
// Any IPv4 DELROUTE/DELRULE counts — Cilium pod-route churn emits
// them by the hundred — so on top of the burst debounce restores are
// capped to one per routeGuardMinRestore: a fire inside the window is
// re-armed for the window's end rather than dropped, so the trailing
// edge of a flap still lands exactly one restore. Filtering DELRULE
// by FRA_PRIORITY or DELROUTE by rtm_table was considered and
// dropped: the bash guard matched the pub/marker tables and prefs
// 1400/1490/1500 by NAME in `ip monitor` text — netlink carries only
// numbers that need /etc/iproute2/rt_tables to resolve, which the
// agent can't map host-side cheaply. The rate limit already bounds
// the exec cost (~20 subcommands per restore); the is-active gate
// bounds the rest.
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
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
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
	// silent after the first log line.
	routeGuardErrEvery = 30
)

// Netns magic-link paths for the host-netns bind selection.
// routeInitNetns is a var so tests can point pid 1's entry at a
// fixture path; routeSelfNetns is always the real own-netns link —
// it is also the setns restore target inside bindInNetns.
var routeInitNetns = "/proc/1/ns/net"

const routeSelfNetns = "/proc/self/ns/net"

// --- netlink socket (host netns) ---

// bindRouteSocket creates the subscribed NETLINK_ROUTE socket — the
// bash `ip monitor rule route` without the forked process.
func bindRouteSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_RULE,
	}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// sameNetns reports whether two /proc/<pid>/ns/net magic links name
// the same network namespace — the hostNetwork check (the pod's own
// netns IS the host's when the inode matches pid 1's).
func sameNetns(a, b string) bool {
	ai, aerr := os.Stat(a)
	bi, berr := os.Stat(b)
	return aerr == nil && berr == nil && os.SameFile(ai, bi)
}

// openRouteNetlink returns the bound socket in the HOST network
// namespace. Selection order matches the DaemonSet's actual mounts:
//
//   - hostNetwork: /proc/self/ns/net == /proc/1/ns/net → bind
//     directly, no setns at all (the common case on workers).
//   - hostPID: /proc/1/ns/net is host init's netns → setns into it
//     for the socket creation — reachable WITHOUT any /host/proc
//     mount (the DS mounts individual hostPaths only, so this is the
//     path that keeps the guard alive containerized).
//   - <hostRoot>/proc/1/ns/net: last fallback for a pod with neither
//     flag but a mounted host /proc.
func openRouteNetlink(hostRoot string) (int, error) {
	if sameNetns(routeSelfNetns, routeInitNetns) {
		return bindRouteSocket()
	}
	fd, err := bindInNetns(routeInitNetns)
	if err == nil {
		return fd, nil
	}
	if hostRoot != "" && hostRoot != "/" {
		if ffd, ferr := bindInNetns(
			filepath.Join(hostRoot, "proc/1/ns/net")); ferr == nil {
			return ffd, nil
		} else {
			err = fmt.Errorf("%w (host-root fallback: %v)", err, ferr)
		}
	}
	return -1, err
}

// bindInNetns binds the route socket inside the netns at nsPath —
// the same namespace the runHostCmd seam reaches with `nsenter -t 1
// -n`. setns(2) is per-thread: the calling thread is locked,
// switched, and switched back; the socket keeps the creating netns.
//
// If the restore fails the thread must NOT go back to the runtime —
// a goroutine scheduled on it would silently execute in the host
// netns. The bound fd is closed and the goroutine exits via
// runtime.Goexit while the thread stays locked, which makes the
// runtime destroy the thread instead of reusing it (the safe setns
// pattern). The goroutine's defers still run (the ns fds close).
func bindInNetns(nsPath string) (int, error) {
	self, err := unix.Open(routeSelfNetns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("self netns: %w", err)
	}
	defer unix.Close(self)
	host, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("host netns %s: %w", nsPath, err)
	}
	defer unix.Close(host)
	runtime.LockOSThread()
	if err := unix.Setns(host, unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return -1, fmt.Errorf("setns %s: %w", nsPath, err)
	}
	fd, serr := bindRouteSocket()
	if rerr := unix.Setns(self, unix.CLONE_NEWNET); rerr != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		slog.Error("route-guard: setns restore failed — parking "+
			"thread in the host netns and exiting the guard goroutine",
			"error", rerr, "subsystem", "nethealth")
		runtime.Goexit()
		panic("unreachable")
	}
	runtime.UnlockOSThread()
	return fd, serr
}

// scanDeleteEvents reports whether buf carries at least one nlmsg of
// type RTM_DELROUTE or RTM_DELRULE — the only events the bash guard
// reacted to (`*Deleted*` lines). Netlink headers are host byte order
// — binary.NativeEndian matches the kernel layout without unsafe.
func scanDeleteEvents(buf []byte) bool {
	for len(buf) >= unix.NLMSG_HDRLEN {
		ln := int(binary.NativeEndian.Uint32(buf[0:4]))
		typ := binary.NativeEndian.Uint16(buf[4:6])
		if ln < unix.NLMSG_HDRLEN || ln > len(buf) {
			return false
		}
		switch typ {
		case unix.RTM_DELROUTE, unix.RTM_DELRULE:
			return true
		}
		buf = buf[nlmsgAlign(ln):]
	}
	return false
}

func nlmsgAlign(ln int) int {
	return (ln + int(unix.NLMSG_ALIGNTO) - 1) &^ (int(unix.NLMSG_ALIGNTO) - 1)
}

// --- the guard loop ---

// nebulaUpScript is the restore path as seen from the HOST mount
// namespace — the same path systemd's ExecStartPost ran.
func nebulaUpScript(net string) string {
	return "/etc/nebula/" + net + "/nebula-up.sh"
}

// nebulaUpExists stats the restore script through HostRoot — the
// no-op gate for plain workers without a converged nebula mesh.
func (n *NetHealth) nebulaUpExists(wd *watchdogconf.Config) bool {
	if wd.NebulaNet == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(n.cfg.HostRoot,
		"etc/nebula", wd.NebulaNet, "nebula-up.sh"))
	return err == nil && fi.Mode().IsRegular()
}

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

// routeGuard is the outer lifecycle: poll for nebula-up.sh, bind the
// netlink socket, monitor, reopen on read error — the bash outer
// `while true; ip monitor; sleep 2` loop. Spawned once per NetHealth
// via routeGuardOnce in Run() — an agent panic-restart of Run must
// not double-bind sockets or double-restore.
func (n *NetHealth) routeGuard(ctx context.Context) {
	open := n.cfg.openRouteSocket
	if open == nil {
		hostRoot := n.cfg.HostRoot
		open = func() (int, error) { return openRouteNetlink(hostRoot) }
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
				n.appendLog(fmt.Sprintf(
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
	events := make(chan struct{}, 16)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeFd := func() { closeOnce.Do(func() { unix.Close(fd) }) }
	defer closeFd()
	go func() {
		defer close(done)
		defer closeFd()
		buf := make([]byte, 64*1024)
		for {
			nr, err := unix.Read(fd, buf)
			if err != nil || nr == 0 {
				// err: closed/failing fd; nr==0: peer EOF. A close
				// triggered by ctx cancel is the normal shutdown —
				// only unexpected read failures are worth a trail.
				if err != nil && ctx.Err() == nil {
					slog.Debug("route-guard: netlink read failed — "+
						"socket will reopen",
						"subsystem", "nethealth", "error", err)
				}
				return
			}
			if scanDeleteEvents(buf[:nr]) {
				select {
				case events <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
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

// restoreRouteGuard re-runs /etc/nebula/<net>/nebula-up.sh — the
// restore() the bash guard ran per burst. The script is idempotent
// and reads the overlay state file itself, so it only writes ip
// rules when nebula actually owns the dataplane (no rule stomping
// while overlay=tinc).
func (n *NetHealth) restoreRouteGuard(ctx context.Context) {
	wd := n.watchdogConf()
	if !wd.SignalEnabled(checkRouteGuard) {
		slog.Debug("route-guard: restore skipped — kill switch off "+
			"(WD_SIG_ROUTE_GUARD=off)", "subsystem", "nethealth")
		return
	}
	if !n.nebulaUpExists(wd) {
		slog.Debug("route-guard: restore skipped — nebula-up.sh gone "+
			"mid-run", "subsystem", "nethealth", "net", wd.NebulaNet)
		return
	}
	// bash gate: restore only while `systemctl is-active
	// nebula@<net>` says active — a deliberately stopped unit must
	// not be resurrected by its own delete events (inactive,
	// deactivating AND no-systemd all count as down; activating is
	// the unit's own ExecStartPost job).
	if n.cfg.Systemd == nil {
		slog.Debug("route-guard: restore skipped — no systemd client",
			"subsystem", "nethealth", "unit", "nebula@"+wd.NebulaNet)
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "nebula@"+wd.NebulaNet)
	if err != nil {
		// Fail closed: an unanswerable probe (dbus down, systemctl
		// missing) must not resurrect a possibly-stopped unit —
		// skip the restore this cycle.
		slog.Warn("route-guard: restore skipped — is-active probe "+
			"failed (fail closed)",
			"subsystem", "nethealth", "unit", "nebula@"+wd.NebulaNet,
			"error", err)
		return
	}
	if !active {
		slog.Debug("route-guard: restore skipped — nebula unit not "+
			"active",
			"subsystem", "nethealth", "unit", "nebula@"+wd.NebulaNet)
		return
	}
	script := nebulaUpScript(wd.NebulaNet)
	// runMountCmd = nsenter -t 1 -m -n -- : the script gets the host
	// mount+net namespaces (host iptables/nft/sysctl, host /etc
	// files) — identical environment to the unit's ExecStartPost.
	if out, err := n.cfg.runMountCmd(ctx, []string{script}); err != nil {
		n.cycles.WithLabelValues(checkRouteGuard, "restore_error").Inc()
		n.appendLog(fmt.Sprintf("route-guard: %s failed: %v (%s)",
			script, err, trimRunErr(out)))
		return
	}
	n.actions.WithLabelValues(checkRouteGuard, "restored").Inc()
	n.appendLog("ACTION: route-guard re-ran nebula-up.sh after netlink delete")
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
