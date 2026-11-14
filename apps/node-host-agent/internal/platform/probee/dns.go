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
	"time"
)

// buildDNSAQuery builds a minimal RFC 1035 A-record query for name.
func buildDNSAQuery(name string, id uint16) []byte {
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
}

// validDNSReply reports whether buf echoes q's id with the QR bit set.
func validDNSReply(buf, q []byte) bool {
	return len(buf) >= 4 && buf[0] == q[0] && buf[1] == q[1] && buf[2]&0x80 != 0
}

// DNSQuery sends one minimal A-record query for name to addr over
// UDP and reports whether a well-formed reply returns before the
// deadline — the node-local-dns :53 datapath probe. Any reply
// matching the query id with the QR bit set proves the listener is
// alive: NXDOMAIN/SERVFAIL still mean the server answers; silence
// means the datapath is wedged. ctx bounds the dial; timeout still
// bounds the whole exchange via the conn deadline.
//
// Mirrors workerhygiene.probeDNSUDP (cilium.go).
func DNSQuery(ctx context.Context, addr, name string, timeout time.Duration) bool {
	q := buildDNSAQuery(name, uint16(time.Now().UnixNano()))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
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
// same id/QR-bit contract. ctx bounds the dial; timeout still
// bounds the whole exchange via the conn deadline.
func DNSQueryTCP(ctx context.Context, addr, name string, timeout time.Duration) bool {
	q := buildDNSAQuery(name, uint16(time.Now().UnixNano()))
	// TCP framing: 2-byte big-endian length prefix on both directions.
	frame := make([]byte, 2+len(q))
	frame[0], frame[1] = byte(len(q)>>8), byte(len(q))
	copy(frame[2:], q)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
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
	if n < 4 || n > 4096 {
		return false
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return validDNSReply(buf, q)
}
