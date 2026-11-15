// dnsprobe_test.go — coverage for the hand-rolled stub-resolver
// probe: packet build/parse bounds, the QR-bit response check,
// NXDOMAIN semantics, the TC→TCP fallback, and the ctx-deadline
// clamp on the exchange timeout.
package hostconfig

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// dnsTestResp builds a response datagram: ID/flags fixed, the
// question section copied verbatim from q, `an` A records appended.
func dnsTestResp(q []byte, flags uint16, an int) []byte {
	b := []byte{byte(dnsQueryID >> 8), byte(dnsQueryID & 0xff),
		byte(flags >> 8), byte(flags & 0xff),
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT filled below
		0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(b[6:8], uint16(an))
	b = append(b, q[12:]...) // question section verbatim
	for i := 0; i < an; i++ {
		b = append(b,
			0xc0, 0x0c, // name = pointer to question name
			0x00, 0x01, // TYPE A
			0x00, 0x01, // CLASS IN
			0x00, 0x00, 0x00, 0x3c, // TTL 60
			0x00, 0x04, // RDLENGTH
			93, 184, byte(216+i), 34)
	}
	return b
}

func TestDNSQueryPacket(t *testing.T) {
	q, err := dnsQueryPacket("ns1.example.com")
	if err != nil {
		t.Fatalf("dnsQueryPacket: %v", err)
	}
	if len(q) < 12 || q[4] != 0x00 || q[5] != 0x01 {
		t.Fatalf("bad header: %x", q[:12])
	}
	for _, bad := range []string{"", ".", "a..b", strings.Repeat("x", 64) + ".com"} {
		if _, err := dnsQueryPacket(bad); err == nil {
			t.Fatalf("dnsQueryPacket(%q) succeeded, want error", bad)
		}
	}
}

func TestDNSParseA(t *testing.T) {
	q, err := dnsQueryPacket("probe.test")
	if err != nil {
		t.Fatal(err)
	}
	// QR=1, rcode=0, one A answer → the address parses out.
	ips, tc, err := dnsParseA(dnsTestResp(q, 0x8180, 1))
	if err != nil || tc {
		t.Fatalf("parse: ips=%v tc=%v err=%v", ips, tc, err)
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("ips = %v", ips)
	}
	// NXDOMAIN (rcode 3) → empty list, no error (dig +short parity).
	ips, _, err = dnsParseA(dnsTestResp(q, 0x8183, 0))
	if err != nil || len(ips) != 0 {
		t.Fatalf("nxdomain: ips=%v err=%v", ips, err)
	}
	// QR=0 — a query/echo must never parse as an answer.
	if _, _, err = dnsParseA(dnsTestResp(q, 0x0100, 1)); err == nil {
		t.Fatal("QR=0 response parsed without error")
	}
	// SERVFAIL (rcode 2) propagates.
	if _, _, err = dnsParseA(dnsTestResp(q, 0x8182, 0)); err == nil {
		t.Fatal("servfail parsed without error")
	}
	// TC=1 surfaces so the caller falls back to TCP.
	if _, tc, err = dnsParseA(dnsTestResp(q, 0x8380, 0)); err != nil || !tc {
		t.Fatalf("tc flag: tc=%v err=%v", tc, err)
	}
	// Truncated datagram errors.
	if _, _, err = dnsParseA(dnsTestResp(q, 0x8180, 1)[:20]); err == nil {
		t.Fatal("truncated response parsed without error")
	}
}

// useStubAddr points dnsStubAddr at addr for the test's duration.
func useStubAddr(t *testing.T, addr string) {
	t.Helper()
	old := dnsStubAddr
	dnsStubAddr = addr
	t.Cleanup(func() { dnsStubAddr = old })
}

// udpAnswer serves ONE query with resp.
func udpAnswer(t *testing.T, l *net.UDPConn, resp []byte) {
	t.Helper()
	go func() {
		buf := make([]byte, 4096)
		_, peer, err := l.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = l.WriteToUDP(resp, peer)
	}()
}

func TestDNSExchangeUDP(t *testing.T) {
	ul, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	useStubAddr(t, ul.LocalAddr().String())

	q, err := dnsQueryPacket("probe.test")
	if err != nil {
		t.Fatal(err)
	}
	udpAnswer(t, ul, dnsTestResp(q, 0x8180, 1))
	ips, tc, err := dnsExchange(context.Background(), "udp", q)
	if err != nil || tc {
		t.Fatalf("exchange: ips=%v tc=%v err=%v", ips, tc, err)
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("ips = %v", ips)
	}
}

func TestDNSExchangeTCPFallback(t *testing.T) {
	// TC=1 on UDP must trigger the TCP re-ask. Serve the truncated
	// flag on UDP and the real answer on TCP at the SAME addr —
	// bind TCP first, then UDP on its port.
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	port := tl.Addr().(*net.TCPAddr).Port
	ul, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	useStubAddr(t, ul.LocalAddr().String())

	q, err := dnsQueryPacket("probe.test")
	if err != nil {
		t.Fatal(err)
	}
	resp := dnsTestResp(q, 0x8180, 1)
	udpAnswer(t, ul, dnsTestResp(q, 0x8380, 0)) // TC=1, no answers
	go func() {
		c, err := tl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		lb := make([]byte, 2)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb))
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		_, _ = c.Write(out)
	}()

	ips, err := probeLocalDNS(context.Background(), "probe.test")
	if err != nil {
		t.Fatalf("probeLocalDNS: %v", err)
	}
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("ips = %v", ips)
	}
}

func TestDNSExchangeCtxDeadlineClamped(t *testing.T) {
	ul, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	useStubAddr(t, ul.LocalAddr().String())

	// Server that reads queries but never answers.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := ul.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	q, err := dnsQueryPacket("probe.test")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err = dnsExchange(ctx, "udp", q); err == nil {
		t.Fatal("exchange succeeded against a silent stub")
	}
	// The caller's 150ms deadline — not the 3s probe budget — must
	// bound the exchange.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("exchange took %v — ctx deadline not applied", elapsed)
	}
}
