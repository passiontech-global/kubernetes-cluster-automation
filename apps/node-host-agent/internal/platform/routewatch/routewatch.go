// Package routewatch owns the NETLINK_ROUTE socket mechanics a
// route guard needs: binding a subscribed netlink socket inside
// the HOST network namespace and decoding the nlmsg/rtattr wire
// format the event filters build on. It is the kernel-interface
// half extracted from nethealth's routeguard.go (the Go port of
// nebula-route-guard.sh) — the subsystem keeps the policy (which
// tables, rule prefs and ifindex count as its dataplane), this
// package keeps the plumbing.
//
// The socket must live in the HOST network namespace. The
// DaemonSet runs hostNetwork + hostPID and mounts individual
// hostPaths only — there is NO /host/proc mount, so
// <hostRoot>/proc/1/ns/net is not reachable on workers. Instead:
// hostNetwork makes the pod's own netns the host's —
// /proc/self/ns/net and /proc/1/ns/net are the same inode, so
// Bind binds directly with no setns at all. On a non-hostNetwork
// hostPID pod /proc/1/ns/net is still host init's netns → setns
// into it for the socket creation (a socket keeps the netns it
// was created in). Only when pid-1's entry can't be used at all
// does Bind fall back to a mounted host /proc under
// <hostRoot>/proc/1/ns/net.
package routewatch

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// InitNetns is the /proc magic link for pid 1's netns — a var so
// tests can point pid 1's entry at a fixture path (the host-netns
// bind selection below reads it).
var InitNetns = "/proc/1/ns/net"

// SelfNetns is always the real own-netns link — it is also the
// setns restore target inside BindInNetns.
const SelfNetns = "/proc/self/ns/net"

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
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// SameNetns reports whether two /proc/<pid>/ns/net magic links name
// the same network namespace — the hostNetwork check (the pod's own
// netns IS the host's when the inode matches pid 1's).
func SameNetns(a, b string) bool {
	ai, aerr := os.Stat(a)
	bi, berr := os.Stat(b)
	return aerr == nil && berr == nil && os.SameFile(ai, bi)
}

// Bind returns the bound socket in the HOST network namespace.
// Selection order matches the DaemonSet's actual mounts:
//
//   - hostNetwork: /proc/self/ns/net == /proc/1/ns/net → bind
//     directly, no setns at all (the common case on workers).
//   - hostPID: /proc/1/ns/net is host init's netns → setns into it
//     for the socket creation — reachable WITHOUT any /host/proc
//     mount (the DS mounts individual hostPaths only, so this is the
//     path that keeps the guard alive containerized).
//   - <hostRoot>/proc/1/ns/net: last fallback for a pod with neither
//     flag but a mounted host /proc.
func Bind(hostRoot string) (int, error) {
	if SameNetns(SelfNetns, InitNetns) {
		return bindRouteSocket()
	}
	fd, err := BindInNetns(InitNetns)
	if err == nil {
		return fd, nil
	}
	if hostRoot != "" && hostRoot != "/" {
		if ffd, ferr := BindInNetns(
			filepath.Join(hostRoot, "proc/1/ns/net")); ferr == nil {
			return ffd, nil
		} else {
			err = fmt.Errorf("%w (host-root fallback: %v)", err, ferr)
		}
	}
	return -1, err
}

// BindInNetns binds the route socket inside the netns at nsPath —
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
func BindInNetns(nsPath string) (int, error) {
	self, err := unix.Open(SelfNetns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("self netns: %w", err)
	}
	defer func() { _ = unix.Close(self) }()
	host, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("host netns %s: %w", nsPath, err)
	}
	defer func() { _ = unix.Close(host) }()
	runtime.LockOSThread()
	if err := unix.Setns(host, unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return -1, fmt.Errorf("setns %s: %w", nsPath, err)
	}
	fd, serr := bindRouteSocket()
	if rerr := unix.Setns(self, unix.CLONE_NEWNET); rerr != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
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
