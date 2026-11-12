//go:build linux

// netlinkx_linux.go — the agent's Go-native host-network reader:
// the replacement for `nsenter ip route/rule/link` and
// `ss`-style socket-state probes that used to fork per cycle. It
// reads the ROUTE TABLE, POLICY RULES, LINK STATE and TCP
// socket-state counts through vishvananda/netlink +
// NETLINK_SOCK_DIAG, plus the cheap /proc/<pid>/net/sockstat{,6}
// aggregates (sockstat_linux.go).
//
// Netns contract: the agent pod runs in its OWN network namespace
// unless it is hostNetwork — its netlink view would show pod routes,
// not the host's. SameNetNS compares (dev,ino) of
// /proc/self/ns/net vs /proc/<pid>/ns/net (hostPID:true makes
// /proc the HOST proc, so pid 1 is host init). Route/rule/link
// reads bind a netlink.Handle inside the target ns once via
// netlink.NewHandleAt (vishvananda/netns) — the kernel keeps the
// socket in that ns, so the calling thread NEVER carries a foreign
// netns between calls. The raw NETLINK_SOCK_DIAG dump in
// sockstat_linux.go still needs a scoped setns; InNetNS runs it on
// a dedicated OS thread that is quarantined (never UnlockOSThread)
// when the restore fails or fn panics — a dirty M returned to the
// scheduler pool would hand the host netns to unrelated goroutines.
//
// linux-only by construction — the agent only builds for linux.
package netlinkx

import (
	"fmt"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// netNSPath is /proc/<pid>/ns/net under the HOST proc view
// (hostPID:true mounts host /proc at /proc even when HostRoot is
// /host — the nsenter wrap covers commands, not this file).
func netNSPath(pid int) string {
	return fmt.Sprintf("/proc/%d/ns/net", pid)
}

// SameNetNS reports whether the process's network namespace is the
// same inode as pid's — hostNetwork pods share it (direct netlink
// calls cost nothing extra); regular pods must bind into it first.
func SameNetNS(pid int) (bool, error) {
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return false, fmt.Errorf("stat self netns: %w", err)
	}
	other, err := os.Stat(netNSPath(pid))
	if err != nil {
		return false, fmt.Errorf("stat pid %d netns: %w", pid, err)
	}
	return os.SameFile(self, other), nil
}

// InNetNS runs fn with the calling thread's network namespace set
// to pid's — a no-op wrapper when already shared. fn executes on a
// dedicated goroutine locked to its OS thread for the setns window;
// the original ns fd is restored before the thread unlocks. When
// the restore fails or fn panics the thread is QUARANTINED: the
// goroutine parks forever without UnlockOSThread, so a possibly
// foreign-netns M never re-enters the scheduler pool — leaking one
// thread is cheaper than polluting every goroutine that lands on it.
func InNetNS(pid int, fn func() error) error {
	same, err := SameNetNS(pid)
	if err != nil {
		return err
	}
	if same {
		return fn()
	}
	type outcome struct{ err error }
	done := make(chan outcome, 1)
	go func() {
		runtime.LockOSThread()
		// dirty flips true the moment setns(target) succeeds —
		// from there on the thread MUST NOT return to the pool
		// unless the original ns is provably restored.
		dirty := false
		defer func() {
			if dirty {
				select {} // quarantine: park the goroutine+M forever
			}
			runtime.UnlockOSThread()
		}()
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{err: fmt.Errorf("netns fn panic: %v", r)}
			}
		}()

		self, err := os.Open("/proc/self/ns/net")
		if err != nil {
			done <- outcome{err: fmt.Errorf("open self netns: %w", err)}
			return
		}
		defer func() { _ = self.Close() }()
		target, err := os.Open(netNSPath(pid))
		if err != nil {
			done <- outcome{err: fmt.Errorf("open pid %d netns: %w", pid, err)}
			return
		}
		defer func() { _ = target.Close() }()

		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- outcome{err: fmt.Errorf("setns pid %d netns: %w", pid, err)}
			return // still in the original ns — safe to unlock
		}
		dirty = true
		fnErr := fn()
		// Restore unconditionally — even on fn error the thread
		// must not carry the host ns into unrelated work.
		if rerr := unix.Setns(int(self.Fd()), unix.CLONE_NEWNET); rerr != nil {
			done <- outcome{err: fmt.Errorf("restore netns: %w (fn err: %v)", rerr, fnErr)}
			return // dirty stays true — the M is quarantined
		}
		dirty = false
		done <- outcome{err: fnErr}
	}()
	return (<-done).err
}

// routeHandle returns a NETLINK_ROUTE handle bound to pid's netns.
// NewHandleAt setns'es only for the socket bind (inside
// nl.GetNetlinkSocketAt's own locked thread window) — the sockets
// then live in the target ns permanently, so Routes/Rules/Links/
// LinkByName never touch the calling thread's netns at all.
func routeHandle(pid int) (*netlink.Handle, error) {
	same, err := SameNetNS(pid)
	if err != nil {
		return nil, err
	}
	if same {
		return netlink.NewHandle(unix.NETLINK_ROUTE)
	}
	ns, err := netns.GetFromPid(pid)
	if err != nil {
		return nil, fmt.Errorf("open pid %d netns: %w", pid, err)
	}
	defer func() { _ = ns.Close() }()
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink handle in pid %d netns: %w", pid, err)
	}
	return h, nil
}

// Routes returns every route of pid's netns across ALL routing
// tables — `ip route show table all` parity. The RT_FILTER_TABLE
// mask with RT_TABLE_UNSPEC keeps the kernel's unfiltered dump:
// policy-routing tables (100..103, cilium/kube-ipvs shapes) are
// real routes the old table-blind RouteList could miss.
func Routes(pid int) ([]netlink.Route, error) {
	h, err := routeHandle(pid)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
}

// Rules returns the policy routing rules of pid's netns —
// `ip rule show` parity.
func Rules(pid int) ([]netlink.Rule, error) {
	h, err := routeHandle(pid)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.RuleList(netlink.FAMILY_ALL)
}

// Links returns every link in pid's netns with its admin/oper
// state — `ip link show` parity.
func Links(pid int) ([]netlink.Link, error) {
	h, err := routeHandle(pid)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.LinkList()
}

// LinkByName resolves one interface by name in pid's netns.
func LinkByName(pid int, name string) (netlink.Link, error) {
	h, err := routeHandle(pid)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.LinkByName(name)
}
