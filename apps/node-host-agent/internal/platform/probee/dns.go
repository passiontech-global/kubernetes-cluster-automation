// dns.go — the hand-rolled UDP DNS datapath probe. The module has no
// dns library dependency and needs none: the probe only proves the
// resolver listener answers, so a minimal wire-format A-record query
// plus an id/QR-bit reply check is the whole contract.
package probee

import (
	"io"
	"net"
	"strings"
	"time"
)

// DNSQuery sends one minimal A-record query for name to addr over
// UDP and reports whether a well-formed reply returns before the
// deadline — the node-local-dns :53 datapath probe. Any reply
// matching the query id with the QR bit set proves the listener is
// alive: NXDOMAIN/SERVFAIL still mean the server answers; silence
// means the datapath is wedged.
//
// Mirrors workerhygiene.probeDNSUDP (cilium.go).
func DNSQuery(addr, name string, timeout time.Duration) bool {
	id := uint16(time.Now().UnixNano())
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
	conn, err := net.DialTimeout("udp", addr, timeout)
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
	return err == nil && n >= 4 && buf[0] == q[0] && buf[1] == q[1] &&
		buf[2]&0x80 != 0
}

// DNSQueryTCP is the server-speaks-first-ports TCP :53 twin of DNSQuery: the same
// minimal A-record query carried over TCP, where every DNS message
// is prefixed with a 2-byte length (RFC 1035 §4.2.2). UDP :53 can
// stay alive while the TCP listener wedges — the TC=1 truncation
// fallback every large SRV/A response depends on — so a node whose
// UDP probe passes can still blackhole headless-StatefulSet lookups.
// The reply check reads the length-prefixed frame and applies the
// same id/QR-bit contract.
func DNSQueryTCP(addr, name string, timeout time.Duration) bool {
	id := uint16(time.Now().UnixNano())
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
	// TCP framing: 2-byte big-endian length prefix on both directions.
	frame := []byte{byte(len(q) >> 8), byte(len(q))}
	frame = append(frame, q...)
	conn, err := net.DialTimeout("tcp", addr, timeout)
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
	return buf[0] == q[0] && buf[1] == q[1] && buf[2]&0x80 != 0
}
