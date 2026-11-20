// dns.go — the hand-rolled UDP DNS datapath probe. The module has no
// dns library dependency and needs none: the probe only proves the
// resolver listener answers, so a minimal wire-format A-record query
// plus an id/QR-bit reply check is the whole contract.
package probee

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

var dnsQuerySeq atomic.Uint32

func nextDNSQueryID() uint16 {
	return uint16(dnsQuerySeq.Add(1)) ^ uint16(time.Now().UnixNano())
}

// buildDNSAQuery builds a minimal RFC 1035 A-record query for name.
func buildDNSAQuery(name string, id uint16) []byte {
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
}

// dnsHeaderLen is the fixed RFC 1035 header size (ID, flags and the
// four count fields). A datagram shorter than this has no usable
// id/flags to verify — accepting a 4-byte short read as a live
// resolver turned truncated/stray packets into false positives.
const dnsHeaderLen = 12

// validDNSReply reports whether buf is a full DNS header echoing q's
// id with the QR bit set.
func validDNSReply(buf, q []byte) bool {
	return len(buf) >= dnsHeaderLen &&
		buf[0] == q[0] && buf[1] == q[1] && buf[2]&0x80 != 0
}

// probeDeadline is the earlier of ctx's deadline and now+timeout. The
// conn deadline must never outlive the caller: with timeout=5s and
// a ctx cancelled at 100ms, a wedged resolver/server used to hold the
// read until 5s even though the caller had long given up.
func probeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return deadline
}

// DNSQuery sends one minimal A-record query for name to addr over
// UDP and reports whether a well-formed reply returns before the
// deadline — the node-local-dns :53 datapath probe. Any reply
// matching the query id with the QR bit set proves the listener is
// alive: NXDOMAIN/SERVFAIL still mean the server answers; silence
// means the datapath is wedged. The conn deadline is the earlier of
// ctx's deadline and now+timeout, so a caller's cancellation bounds
// the whole exchange, not just the dial.
//
// Mirrors workerhygiene.probeDNSUDP (cilium.go).
func DNSQuery(ctx context.Context, addr, name string, timeout time.Duration) bool {
	q := buildDNSAQuery(name, nextDNSQueryID())
	deadline := probeDeadline(ctx, timeout)
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	// ID echo + QR bit set (a response, not another query or a stray
	// datagram sharing the id).
	return err == nil && validDNSReply(buf[:n], q)
}

// DNSQueryTCP is the server-speaks-first-ports TCP :53 twin of DNSQuery: the same
// minimal A-record query carried over TCP, where every DNS message
// is prefixed with a 2-byte length (RFC 1035 §4.2.2). UDP :53 can
// stay alive while the TCP listener wedges — the TC=1 truncation
// fallback every large SRV/A response depends on — so a node whose
// UDP probe passes can still blackhole headless-StatefulSet lookups.
// The reply check reads the length-prefixed frame and applies the
// same id/QR-bit contract. As in DNSQuery, the conn deadline is the
// earlier of ctx's deadline and now+timeout.
func DNSQueryTCP(ctx context.Context, addr, name string, timeout time.Duration) bool {
	q := buildDNSAQuery(name, nextDNSQueryID())
	deadline := probeDeadline(ctx, timeout)
	// TCP framing: 2-byte big-endian length prefix on both directions.
	frame := make([]byte, 2+len(q))
	frame[0], frame[1] = byte(len(q)>>8), byte(len(q))
	copy(frame[2:], q)
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(frame); err != nil {
		return false
	}
	// Read the 2-byte length prefix, then exactly that many bytes —
	// a partial frame or a mismatched id is a failed probe.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	// A DNS message needs the full 12-byte RFC 1035 header before
	// its id/QR bits mean anything. The old n<4 floor let a 4-8 byte
	// frame through to ReadFull (waiting on a body that may never
	// arrive); match the UDP path's validDNSReply requirement and
	// reject short frames straight from the length prefix.
	if n < dnsHeaderLen || n > 4096 {
		return false
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return validDNSReply(buf, q)
}
