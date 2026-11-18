package netlinkx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRouteHandleRulesLinkAddrsAndLinkDel(t *testing.T) {
	pid := os.Getpid()
	rules, err := Rules(pid)
	if err != nil {
		t.Fatalf("Rules(%d): %v", pid, err)
	}
	if len(rules) == 0 {
		t.Fatal("expected at least one routing rule in current netns")
	}

	addrs, err := LinkAddrs(pid, "lo")
	if err != nil {
		t.Fatalf("LinkAddrs(lo): %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address on lo")
	}

	// Non-existent interface returns an error without mutating anything.
	if err := LinkDel(pid, "nonexistent-veth-xyz"); err == nil {
		t.Fatal("expected LinkDel on missing interface to fail")
	}
	// Invalid pid fails routeHandle cleanly.
	if _, err := Rules(-1); err == nil {
		t.Fatal("expected Rules(-1) to fail")
	}
}

func TestListenAddrsAndDestroyListenersNoMatch(t *testing.T) {
	pid := os.Getpid()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addrs, err := ListenAddrs(pid)
	if err != nil {
		t.Fatalf("ListenAddrs(%d): %v", pid, err)
	}
	if _, ok := addrs[ln.Addr().String()]; !ok {
		t.Fatalf("ListenAddrs missing bound listener %s (got %d addrs)", ln.Addr().String(), len(addrs))
	}

	// Pick an unused ephemeral port (bind+close) so destroyListeners finds 0 matches
	// and succeeds without needing CAP_NET_ADMIN.
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unusedPort := uint16(tmpLn.Addr().(*net.TCPAddr).Port)
	_ = tmpLn.Close()

	killed, err := DestroyListenersOnPort(pid, unusedPort)
	if err != nil || killed != 0 {
		t.Fatalf("DestroyListenersOnPort(unused=%d) = (%d,%v), want (0,nil)", unusedPort, killed, err)
	}
}

func TestUDPBoundPorts(t *testing.T) {
	pid := os.Getpid()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	bound, err := UDPBoundPorts(pid)
	if err != nil {
		t.Fatalf("UDPBoundPorts(%d): %v", pid, err)
	}
	if !bound[port] {
		t.Fatalf("UDPBoundPorts missing the bound UDP port %d (got %d ports)", port, len(bound))
	}
}

func TestV6StringAndNoInet6Family(t *testing.T) {
	v4mapped := net.ParseIP("::ffff:127.0.0.53").To16()
	if got := v6String(v4mapped); got != "::ffff:127.0.0.53" {
		t.Fatalf("v6String(v4mapped) = %q, want ::ffff:127.0.0.53", got)
	}
	v6 := net.ParseIP("2001:db8::1").To16()
	if got := v6String(v6); got != "2001:db8::1" {
		t.Fatalf("v6String(v6) = %q, want 2001:db8::1", got)
	}

	if !noInet6Family(fmt.Errorf("wrapped: %w", unix.EAFNOSUPPORT)) {
		t.Fatal("expected EAFNOSUPPORT to be classified as noInet6Family")
	}
	if noInet6Family(errors.New("other")) {
		t.Fatal("unrelated error classified as noInet6Family")
	}
}
