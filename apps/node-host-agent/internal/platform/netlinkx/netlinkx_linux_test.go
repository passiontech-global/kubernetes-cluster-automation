//go:build linux

package netlinkx

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// TestTCPTablesLive creates real TCP sockets in the current netns
// (a listener plus an established pair) and asserts the 1-pass diag
// census counts them — exercises the whole nlmsghdr/inet_diag_msg
// parse against the live kernel, not a fixture.
func TestTCPTablesLive(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
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

	census, err := TCPTables(os.Getpid())
	if err != nil {
		t.Fatalf("TCPTables: %v", err)
	}
	// 1 = TCP_ESTABLISHED. The listener is LISTEN(10); the pair is
	// ESTABLISHED — assert at least the established count grew.
	if census.States[1] < 2 {
		t.Fatalf("expected >=2 ESTABLISHED sockets, got %v", census.States)
	}
	if census.States[10] < 1 {
		t.Fatalf("expected >=1 LISTEN socket, got %v", census.States)
	}
	// The established pair's remote endpoint (127.0.0.1:<port>) must
	// be in the per-tuple table and render through DiagEndpoint.
	found := false
	for key := range census.PerTuple {
		if end := DiagEndpoint(key); strings.HasPrefix(end, "127.0.0.1:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("loopback endpoint missing from PerTuple: %v", census.PerTuple)
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

func TestParseDiagCensusMultiBatchAndMixedFamilies(t *testing.T) {
	mkV4 := func(ip [4]byte, port uint16, state uint8) []byte {
		m := inetDiagMsg(unix.AF_INET, state, 12345, port)
		copy(m[16+24:16+28], ip[:])
		return m
	}
	mkV6 := func(ip [16]byte, port uint16, state uint8) []byte {
		m := inetDiagMsg(unix.AF_INET6, state, 12345, port)
		copy(m[16+24:16+40], ip[:])
		return m
	}

	// Build an IPv6 address whose trailing 12 bytes + port are all 0, plus an
	// IPv4 address sharing the first 4 bytes + port 0: 6-byte vs 18-byte keys
	// must never collide.
	v4IP := [4]byte{10, 0, 0, 1}
	v6ZeroTail := [16]byte{10, 0, 0, 1}

	var trunc [16 + 10]byte
	binary.LittleEndian.PutUint32(trunc[0:4], uint32(len(trunc)))
	trunc[4] = 20 // non-DONE/ERROR type, short payload

	var batch1 []byte
	batch1 = append(batch1, mkV4(v4IP, 0, 1)...)
	batch1 = append(batch1, mkV6(v6ZeroTail, 0, 1)...)
	batch1 = append(batch1, trunc[:]...)

	var batch2 []byte
	batch2 = append(batch2, mkV4(v4IP, 0, 1)...)
	batch2 = append(batch2, mkV4([4]byte{192, 168, 1, 2}, 443, 2)...)
	batch2 = append(batch2, mkV6(v6ZeroTail, 0, 1)...)

	out := TCPCensus{States: map[uint8]int{}, PerTuple: map[string]int{}}
	done1, err := parseDiagCensus(batch1, &out)
	if err != nil || done1 {
		t.Fatalf("batch1=(%v,%v) want (false,nil)", done1, err)
	}
	done2, err := parseDiagCensus(batch2, &out)
	if err != nil || done2 {
		t.Fatalf("batch2=(%v,%v) want (false,nil)", done2, err)
	}

	if out.States[1] != 4 || out.States[2] != 1 {
		t.Fatalf("States=%v want {1:4, 2:1}", out.States)
	}
	if len(out.PerTuple) != 3 {
		t.Fatalf("PerTuple len=%d (%v) want 3 distinct endpoints", len(out.PerTuple), out.PerTuple)
	}

	gotEndpoints := map[string]int{}
	for k, n := range out.PerTuple {
		gotEndpoints[DiagEndpoint(k)] += n
	}
	if gotEndpoints["10.0.0.1:0"] != 2 {
		t.Fatalf("v4 10.0.0.1:0 count=%d want 2", gotEndpoints["10.0.0.1:0"])
	}
	if gotEndpoints["[a00:1::]:0"] != 2 {
		t.Fatalf("v6 [a00:1::]:0 count=%d want 2 (endpoints=%v)", gotEndpoints["[a00:1::]:0"], gotEndpoints)
	}
	if gotEndpoints["192.168.1.2:443"] != 1 {
		t.Fatalf("v4 192.168.1.2:443 count=%d want 1", gotEndpoints["192.168.1.2:443"])
	}
}
