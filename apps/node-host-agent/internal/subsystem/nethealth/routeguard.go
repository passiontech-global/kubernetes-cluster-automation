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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
	// A route-delete burst (interface flap, Cilium churn) can
	// overflow the default netlink receive buffer (~200K) — the
	// kernel then silently drops exactly the DEL events this guard
	// exists to catch. 4MiB is the usual monitor sizing; a failure
	// (rmem_max cap) only logs — a smaller buffer still beats no
	// guard.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET,
		unix.SO_RCVBUF, 4<<20); err != nil {
		logger().Warn("route-guard: SO_RCVBUF 4MiB failed — keeping "+
			"default buffer (delete bursts may lose events)",
			"error", err)
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
		logger().Error("route-guard: setns restore failed — parking "+
			"thread in the host netns and exiting the guard goroutine",
			"error", rerr)
		runtime.Goexit()
		panic("unreachable")
	}
	runtime.UnlockOSThread()
	return fd, serr
}

// --- delete-event decode ---

// The numeric identity of the nebula dataplane — constants mirrored
// from nebula-up.sh (hostconfig templates/nebula-up.sh.j2):
// routeGuardTablePub is the $PUB default — a node that overrode
// interdc_nebula_table_pub carries it in watchdog conf as
// OVERLAY_EGRESS_TABLE (hostconfig writes it there), so the conf
// value wins. $MARK (interdc_nebula_table_marker) and the three
// prefs have no conf counterpart — 101/1400/1490/1500 are the only
// values the script renders: 1400 the fwmark-0x1000 underlay bypass
// shared with tinc, 1490 the marker-CIDR lookup into $MARK, 1500
// the per-target lookups into $PUB.
const (
	routeGuardTablePub   = 100
	routeGuardTableMark  = 101
	routeGuardPrefFwmark = 1400
	routeGuardPrefMarker = 1490
	routeGuardPrefPub    = 1500
	// fibRuleHdrLen is sizeof(struct fib_rule_hdr) — the fixed
	// header a DELRULE payload carries before its rtattr list
	// (x/sys exports no constant for it).
	fibRuleHdrLen = 12
)

// routeEventFilter is the nebula dataplane identity the delete scan
// matches against: the pub/marker routing tables, the rule prefs
// nebula-up.sh owns, and the nebula dev's kernel ifindex (0 =
// unresolved — the RTA_OIF half of the DELROUTE match then stays
// inert, but tables and prefs still catch the rules).
type routeEventFilter struct {
	tables map[uint32]bool
	prefs  map[uint32]bool
	nebIf  uint32
}

// nebulaRouteFilter builds the filter once per socket session —
// cheap: a couple of map writes plus one sysfs read. The ifindex
// resolves through the same /sys/class/net view hostmetrics reads
// (the host netns under hostNetwork — exactly the netns the bound
// socket watches); on a non-hostNetwork pod sysfs shows the pod's
// own netns and the dev simply doesn't resolve.
func (n *NetHealth) nebulaRouteFilter() *routeEventFilter {
	f := &routeEventFilter{
		tables: map[uint32]bool{routeGuardTableMark: true},
		prefs: map[uint32]bool{
			routeGuardPrefFwmark: true,
			routeGuardPrefMarker: true,
			routeGuardPrefPub:    true,
		},
	}
	wd := n.watchdogConf()
	if wd == nil {
		f.tables[routeGuardTablePub] = true
		return f
	}
	pub := uint32(wd.OverlayEgressTable)
	if pub == 0 {
		pub = routeGuardTablePub
	}
	f.tables[pub] = true
	f.nebIf = nebulaIfindex(n.cfg.sysClassNet, wd.NebulaDev)
	return f
}

// nebulaIfindex reads <dir>/<dev>/ifindex — the numeric id netlink
// puts in RTA_OIF. A missing/unreadable dev (down mid-restart,
// nebula not yet up) yields 0 — never a real ifindex, so the OIF
// match stays inert instead of failing open into the CNI flood.
func nebulaIfindex(dir, dev string) uint32 {
	if dev == "" {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(dir, dev, "ifindex"))
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v <= 0 {
		return 0
	}
	return uint32(v)
}

// scanDeleteEvents reports whether buf carries at least one nlmsg a
// restore must answer — the only events the bash guard reacted to
// (`*Deleted*` lines naming the nebula state). Netlink headers are
// host byte order — binary.NativeEndian matches the kernel layout
// without unsafe. Fail-open: a torn header or tail can't be proven
// NOT to be a nebula delete, so it counts.
func (f *routeEventFilter) scanDeleteEvents(buf []byte) bool {
	for len(buf) > 0 {
		if len(buf) < unix.NLMSG_HDRLEN {
			return true
		}
		ln := int(binary.NativeEndian.Uint32(buf[0:4]))
		typ := binary.NativeEndian.Uint16(buf[4:6])
		if ln < unix.NLMSG_HDRLEN || ln > len(buf) {
			return true
		}
		switch typ {
		case unix.RTM_DELROUTE:
			if f.delRouteRelevant(buf[unix.NLMSG_HDRLEN:ln]) {
				return true
			}
		case unix.RTM_DELRULE:
			if f.delRuleRelevant(buf[unix.NLMSG_HDRLEN:ln]) {
				return true
			}
		}
		// The next message sits at the aligned offset — but the
		// kernel may not pad the LAST message to alignment, so the
		// offset can land exactly at or past the buffer end.
		if next := nlmsgAlign(ln); next < len(buf) {
			buf = buf[next:]
		} else {
			return false
		}
	}
	return false
}

// delRouteRelevant decodes an RTM_DELROUTE payload (struct rtmsg +
// rtattrs). Relevant when the route sat in a nebula table (`default
// dev neb1` in $PUB/$MARK) or egressed the nebula dev — the
// marker-base /24 link route lives in table MAIN (254). rtm_table
// is a u8; ids >255 arrive in RTA_TABLE instead, which wins when
// present. Undecodable payloads are relevant (fail-open).
func (f *routeEventFilter) delRouteRelevant(payload []byte) bool {
	if len(payload) < unix.SizeofRtMsg {
		return true // truncated rtmsg — can't prove it isn't ours
	}
	if payload[0] != unix.AF_INET {
		return false // non-IPv4 — never nebula's (no v6 tables/rules)
	}
	attrs, clean := routeAttrs(payload[unix.SizeofRtMsg:],
		unix.RTA_TABLE, unix.RTA_OIF)
	if !clean {
		return true // torn attribute list — can't prove it isn't ours
	}
	table := uint32(payload[4])
	if v, ok := attrs[unix.RTA_TABLE]; ok {
		table = v
	}
	return f.tables[table] ||
		(f.nebIf != 0 && attrs[unix.RTA_OIF] == f.nebIf)
}

// delRuleRelevant decodes an RTM_DELRULE payload (struct
// fib_rule_hdr + rtattrs): relevant when FRA_PRIORITY is a pref
// nebula-up.sh owns. The kernel sends FRA_PRIORITY unconditionally —
// a payload without it, or with a torn attribute list, is
// undecodable → relevant.
func (f *routeEventFilter) delRuleRelevant(payload []byte) bool {
	if len(payload) < fibRuleHdrLen {
		return true
	}
	if payload[0] != unix.AF_INET {
		return false
	}
	attrs, clean := routeAttrs(payload[fibRuleHdrLen:],
		unix.FRA_PRIORITY)
	if !clean {
		return true
	}
	prio, ok := attrs[unix.FRA_PRIORITY]
	if !ok {
		return true
	}
	return f.prefs[prio]
}

// routeAttrs walks a rtattr list and extracts the wanted u32-valued
// attributes. clean=false means the walk hit a torn attribute
// (rta_len shorter than the header or running past the buffer end)
// — the wanted values may sit in the unread tail, so callers treat
// !clean as undecodable. A last attribute whose ALIGNMENT padding
// overruns the buffer is a clean end: the kernel need not pad the
// final attribute of a message.
func routeAttrs(buf []byte, wants ...uint16) (map[uint16]uint32, bool) {
	found := map[uint16]uint32{}
	want := map[uint16]bool{}
	for _, w := range wants {
		want[w] = true
	}
	for len(buf) >= unix.SizeofRtAttr {
		ln := int(binary.NativeEndian.Uint16(buf[0:2]))
		typ := binary.NativeEndian.Uint16(buf[2:4])
		if ln < unix.SizeofRtAttr || ln > len(buf) {
			return found, false
		}
		if want[typ] && ln >= unix.SizeofRtAttr+4 {
			found[typ] = binary.NativeEndian.Uint32(buf[4:8])
		}
		if next := rtaAlign(ln); next < len(buf) {
			buf = buf[next:]
		} else {
			return found, next == len(buf) || ln == len(buf)
		}
	}
	// A <4B residue can't hold an attribute (min rta_len is the
	// header) — treat it as undecodable rather than silently exact.
	return found, len(buf) == 0
}

func nlmsgAlign(ln int) int {
	return (ln + int(unix.NLMSG_ALIGNTO) - 1) &^ (int(unix.NLMSG_ALIGNTO) - 1)
}

func rtaAlign(ln int) int {
	return (ln + int(unix.RTA_ALIGNTO) - 1) &^ (int(unix.RTA_ALIGNTO) - 1)
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
	// The delete filter arms once per socket session: a rebuilt
	// nebula dev (tun recreate) or a watchdog-conf table renumber
	// only re-reads on the next socket reopen. The ifindex read
	// failing is NOT fatal — matching then falls back to
	// tables+prefs.
	filter := n.nebulaRouteFilter()
	events := make(chan struct{}, 16)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeFd := func() { closeOnce.Do(func() { unix.Close(fd) }) }
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

// restoreRouteGuard re-runs /etc/nebula/<net>/nebula-up.sh — the
// restore() the bash guard ran per burst. The script is idempotent
// and reads the overlay state file itself, so it only writes ip
// rules when nebula actually owns the dataplane (no rule stomping
// while overlay=tinc).
func (n *NetHealth) restoreRouteGuard(ctx context.Context) {
	wd := n.watchdogConf()
	if !wd.SignalEnabled(checkRouteGuard) {
		logger().Debug("route-guard: restore skipped — kill switch off " +
			"(WD_SIG_ROUTE_GUARD=off)")
		return
	}
	if !n.nebulaUpExists(wd) {
		logger().Debug("route-guard: restore skipped — nebula-up.sh gone "+
			"mid-run", "net", wd.NebulaNet)
		return
	}
	// bash gate: restore only while `systemctl is-active
	// nebula@<net>` says active — a deliberately stopped unit must
	// not be resurrected by its own delete events (inactive,
	// deactivating AND no-systemd all count as down; activating is
	// the unit's own ExecStartPost job).
	if n.cfg.Systemd == nil {
		logger().Debug("route-guard: restore skipped — no systemd client",
			"unit", "nebula@"+wd.NebulaNet)
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "nebula@"+wd.NebulaNet)
	if err != nil {
		// Fail closed: an unanswerable probe (dbus down, systemctl
		// missing) must not resurrect a possibly-stopped unit —
		// skip the restore this cycle.
		logger().Warn("route-guard: restore skipped — is-active probe "+
			"failed (fail closed)",
			"unit", "nebula@"+wd.NebulaNet,
			"error", err)
		return
	}
	if !active {
		logger().Debug("route-guard: restore skipped — nebula unit not "+
			"active",
			"unit", "nebula@"+wd.NebulaNet)
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
