//go:build linux

package netlinkx

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestParseSockstatV4(t *testing.T) {
	raw := `sockets: used 974
TCP: inuse 121 orphan 0 tw 121 alloc 668 mem 245
UDP: inuse 6 mem 1023
RAW: inuse 0
FRAG: inuse 0 memory 0
`
	s, err := parseSockstatV4(raw)
	if err != nil {
		t.Fatalf("parseSockstatV4: %v", err)
	}
	if s.SocketsUsed != 974 || s.TCP.Inuse != 121 || s.TCP.TimeWait != 121 ||
		s.TCP.Alloc != 668 || s.TCP.Mem != 245 || s.UDP.Inuse != 6 || s.UDP.Mem != 1023 {
		t.Fatalf("unexpected parse: %+v", s)
	}
}

func TestParseSockstatV6(t *testing.T) {
	raw := `TCP6: inuse 68
UDP6: inuse 3
RAW6: inuse 1
FRAG6: inuse 0 memory 0
`
	s, err := parseSockstatV6(raw)
	if err != nil {
		t.Fatalf("parseSockstatV6: %v", err)
	}
	if s.TCPInuse != 68 || s.UDPInuse != 3 || s.RawInuse != 1 {
		t.Fatalf("unexpected parse: %+v", s)
	}
}

// TestSockstatLive reads the test process's own /proc view —
// the file always exists on Linux and the test binary itself
// holds sockets, so the parse must produce sane aggregates.
func TestSockstatLive(t *testing.T) {
	v4, v6, err := Sockstat(os.Getpid()) // own ns is always stat-able
	if err != nil {
		t.Skipf("sockstat unavailable: %v", err)
	}
	if v4.SocketsUsed < 0 || v4.TCP.Inuse < 0 || v6.TCPInuse < 0 {
		t.Fatalf("negative counts: %+v %+v", v4, v6)
	}
}

// TestTCPStatesLive creates real TCP sockets in the current netns
// (a listener plus an established pair) and asserts the diag dump
// counts them — exercises the whole nlmsghdr/inet_diag_msg parse
// against the live kernel, not a fixture.
func TestTCPStatesLive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("dial: %v", err)
	}
	defer conn.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	var srv net.Conn
	select {
	case srv = <-accepted:
		defer srv.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}

	states, err := TCPStates(os.Getpid())
	if err != nil {
		t.Fatalf("TCPStates: %v", err)
	}
	// 1 = TCP_ESTABLISHED. The listener is LISTEN(10); the pair is
	// ESTABLISHED — assert at least the established count grew.
	if states[1] < 2 {
		t.Fatalf("expected >=2 ESTABLISHED sockets, got %v", states)
	}
	if states[10] < 1 {
		t.Fatalf("expected >=1 LISTEN socket, got %v", states)
	}
}

// TestInNetNSRunsFN exercises both branches of the ns compare —
// same-netns dev box runs fn directly; a container hits the
// setns/restore path. Either way fn must execute exactly once.
func TestInNetNSRunsFN(t *testing.T) {
	ran := 0
	if err := InNetNS(os.Getpid(), func() error { ran++; return nil }); err != nil {
		t.Fatalf("InNetNS: %v", err)
	}
	if ran != 1 {
		t.Fatalf("fn ran %d times", ran)
	}
}
