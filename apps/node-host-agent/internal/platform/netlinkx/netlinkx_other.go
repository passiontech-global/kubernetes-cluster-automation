//go:build !linux

// netlinkx_other.go — non-Linux stub: the agent only ships on
// Linux (DaemonSet + standalone systemd); this keeps `go test`
// usable on dev machines, matching the pagecache/dbus stub
// convention.
package netlinkx

import (
	"errors"

	"github.com/vishvananda/netlink"
)

var errNotLinux = errors.New("netlinkx: host netlink is linux-only")

// SameNetNS always fails off Linux — there is no /proc netns.
func SameNetNS(int) (bool, error) { return false, errNotLinux }

// InNetNS refuses off Linux.
func InNetNS(int, func() error) error { return errNotLinux }

// Routes refuses off Linux.
func Routes(int) ([]netlink.Route, error) { return nil, errNotLinux }

// Rules refuses off Linux.
func Rules(int) ([]netlink.Rule, error) { return nil, errNotLinux }

// Links refuses off Linux.
func Links(int) ([]netlink.Link, error) { return nil, errNotLinux }

// LinkByName refuses off Linux.
func LinkByName(int, string) (netlink.Link, error) { return nil, errNotLinux }

// LinkAddrs refuses off Linux.
func LinkAddrs(int, string) ([]netlink.Addr, error) { return nil, errNotLinux }

// LinkDel refuses off Linux.
func LinkDel(int, string) error { return errNotLinux }

// Sockstat reads refuse off Linux.
func Sockstat(int) (SockstatV4, SockstatV6, error) {
	return SockstatV4{}, SockstatV6{}, errNotLinux
}

// TCPTables refuses off Linux.
func TCPTables(int) (TCPCensus, error) { return TCPCensus{}, errNotLinux }

// DestroyListenersOnPort refuses off Linux.
func DestroyListenersOnPort(int, uint16) (int, error) { return 0, errNotLinux }
