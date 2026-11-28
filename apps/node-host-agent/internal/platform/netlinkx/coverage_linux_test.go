package netlinkx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
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
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
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
	tmpLn, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
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

	// A connected UDP client gets an ephemeral sport too — it must NOT
	// be reported as a locally bound (server) port, or every client
	// SrcPort would be classified as a server reply socket and
	// SOCK_DESTROY would be suppressed 100% on a real kernel.
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	client, err := net.DialUDP("udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientPort := uint16(client.LocalAddr().(*net.UDPAddr).Port)

	bound, err := UDPBoundPorts(pid)
	if err != nil {
		t.Fatalf("UDPBoundPorts(%d): %v", pid, err)
	}
	if !bound[port] {
		t.Fatalf("UDPBoundPorts missing the bound UDP port %d (got %d ports)", port, len(bound))
	}
	if bound[clientPort] {
		t.Fatalf("UDPBoundPorts wrongly includes connected client ephemeral port %d", clientPort)
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

func TestDiagRequestProtoFilters(t *testing.T) {
	tcpReq := diagRequestProto(1, unix.AF_INET, unix.IPPROTO_TCP,
		uint32(1)<<tcpStateListen, nil,
		unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	if tcpReq[17] != unix.IPPROTO_TCP {
		t.Fatalf("tcp proto = %d", tcpReq[17])
	}
	if got := binary.LittleEndian.Uint32(tcpReq[20:24]); got != 1<<tcpStateListen {
		t.Fatalf("tcp idiag_states = %#x, want %#x", got, 1<<tcpStateListen)
	}

	wantUDP := uint32(0xFFF) &^ (uint32(1) << tcpStateEstablished)
	udpReq := diagRequestProto(2, unix.AF_INET, unix.IPPROTO_UDP,
		wantUDP, nil,
		unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	if udpReq[17] != unix.IPPROTO_UDP {
		t.Fatalf("udp proto = %d", udpReq[17])
	}
	if got := binary.LittleEndian.Uint32(udpReq[20:24]); got != wantUDP {
		t.Fatalf("udp idiag_states = %#x, want %#x", got, wantUDP)
	}
}

func TestInNetNSRecoveryIncludesStack(t *testing.T) {
	// Exercise InNetNS's goroutine/recover path directly if pid 1 differs or via
	// same-netns path — either way a panic in fn must not crash, and InNetNS
	// returns a descriptive error with stack when running in a separate netns.
	// Here we test same-netns behavior & verify InNetNS handles missing pid cleanly.
	if err := InNetNS(-1, func() error { return nil }); err == nil {
		t.Fatal("InNetNS(-1) expected error")
	}
	// Verify recover formatting when invoked inside InNetNS on a foreign netns
	// (if sameNetNSFor(1) is false) or directly check same-netns call succeeds.
	same, err := SameNetNS(1)
	if err == nil && !same {
		err = InNetNS(1, func() error {
			panic("probe-panic")
		})
		if err == nil || !strings.Contains(err.Error(), "netns fn panic") || !strings.Contains(err.Error(), "TestInNetNSRecoveryIncludesStack") {
			t.Fatalf("InNetNS panic err = %v, want stack trace", err)
		}
	}
}
