// dnsprobe.go — the default DNSProbe: a hand-rolled A-record query
// sent straight to the local stub resolver at 127.0.0.1:53.
//
// It deliberately does NOT use net.Resolver: the Go resolver
// consults /etc/hosts (nsswitch `files dns`) before dialing, so a
// name pinned into /etc/hosts — e.g. pinZoneRecords writing
// ns1.<zone> ahead of the CoreDNS check — would "resolve" without
// any packet ever reaching the stub. That is exactly the signal
// this probe exists to verify (is the local resolver answering?),
// so the query goes out on the wire: UDP first, TCP on truncation,
// A records only — the `dig @127.0.0.1 +time=3 +tries=1` parity
// the bash converge ran.
package hostconfig

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// dnsProbeTimeout is the per-exchange deadline — dig's +time=3.
const dnsProbeTimeout = 3 * time.Second

// dnsQueryID is the fixed transaction id — loopback stub, no
// spoofing concern, and a fixed id keeps the parse check trivial.
const dnsQueryID = 0x1234

// dnsStubAddr is the local resolver endpoint — a var (not const)
// so tests can point the exchange at a loopback listener.
var dnsStubAddr = "127.0.0.1:53"

// probeLocalDNS resolves name's A records against 127.0.0.1:53 and
// returns the address strings — a non-empty list is the "+short
// answered" signal callers test. NXDOMAIN reads as an empty list
// (dig +short parity); transport/servfail errors propagate.
func probeLocalDNS(ctx context.Context, name string) ([]string, error) {
	q, err := dnsQueryPacket(name)
	if err != nil {
		return nil, err
	}
	ips, truncated, err := dnsExchange(ctx, "udp", q)
	if err != nil {
		return nil, err
	}
	if truncated {
		// TC=1: the stub truncated the UDP answer — re-ask over
		// TCP where the 16-bit length prefix carries the full
		// datagram (dig does the same fallback).
		ips, _, err = dnsExchange(ctx, "tcp", q)
		if err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

// dnsQueryPacket builds a minimal recursive-desired A/IN query for
// name ("ns1.zone" or "ns1.zone." both accepted).
func dnsQueryPacket(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("dnsprobe: bad name %q", name)
	}
	// Header: ID, flags=RD, QDCOUNT=1, AN/NS/AR=0.
	b := []byte{byte(dnsQueryID >> 8), byte(dnsQueryID & 0xff),
		0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("dnsprobe: bad name %q", name)
		}
		for i := 0; i < len(label); i++ {
			if label[i] < 0x20 || label[i] > 0x7e {
				return nil, fmt.Errorf("dnsprobe: bad label byte in %q", name)
			}
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	// Root label, QTYPE=A(1), QCLASS=IN(1).
	return append(b, 0x00, 0x00, 0x01, 0x00, 0x01), nil
}

// dnsExchange writes q to the stub over network ("udp"/"tcp") and
// returns the parsed A records plus the response's TC flag.
func dnsExchange(ctx context.Context, network string, q []byte) ([]net.IP, bool, error) {
	var d net.Dialer
	d.Timeout = dnsProbeTimeout
	conn, err := d.DialContext(ctx, network, dnsStubAddr)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = conn.Close() }()
	// The exchange deadline is the EARLIER of the dig-parity 3s
	// budget and the caller's ctx deadline — a flat 3s would let a
	// probe outlive a cycle budget the caller already committed to.
	deadline := time.Now().Add(dnsProbeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, false, err
	}

	payload := q
	if network == "tcp" {
		// TCP DNS frames carry a 2-byte length prefix.
		payload = make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(payload, uint16(len(q)))
		copy(payload[2:], q)
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, false, err
	}

	var msg []byte
	if network == "tcp" {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, false, err
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 12 || n > 65535 {
			return nil, false, fmt.Errorf("dnsprobe: bad tcp length %d", n)
		}
		msg = make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return nil, false, err
		}
	} else {
		// UDP: one datagram is the whole response. 4096 covers any
		// stub answer that fits without truncation.
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, false, err
		}
		msg = buf[:n]
	}
	return dnsParseA(msg)
}

// dnsParseA extracts A-record addresses from a response datagram.
// NXDOMAIN (rcode 3) yields an empty list and no error — the "+short
// answered" contract; other non-zero rcodes are errors.
func dnsParseA(msg []byte) ([]net.IP, bool, error) {
	if len(msg) < 12 {
		return nil, false, errors.New("dnsprobe: short response")
	}
	if msg[0] != byte(dnsQueryID>>8) || msg[1] != byte(dnsQueryID&0xff) {
		return nil, false, errors.New("dnsprobe: transaction id mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		// QR=0 means this is a QUERY (or garbage), not a response —
		// matching on the id alone would parse our own echoed
		// question as an answer.
		return nil, false, errors.New("dnsprobe: QR bit clear — not a response")
	}
	rcode := flags & 0x000f
	if rcode != 0 && rcode != 3 {
		return nil, false, fmt.Errorf("dnsprobe: rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = dnsSkipName(msg, off)
		if err != nil {
			return nil, false, err
		}
		if off+4 > len(msg) {
			return nil, false, errors.New("dnsprobe: truncated question")
		}
		off += 4 // QTYPE + QCLASS
	}
	var ips []net.IP
	for i := 0; i < an; i++ {
		var err error
		off, err = dnsSkipName(msg, off)
		if err != nil {
			return nil, false, err
		}
		if off+10 > len(msg) {
			return nil, false, errors.New("dnsprobe: truncated answer")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		class := binary.BigEndian.Uint16(msg[off+2 : off+4])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, false, errors.New("dnsprobe: truncated rdata")
		}
		if typ == 1 && class == 1 && rdlen == 4 { // A / IN
			ips = append(ips, net.IPv4(msg[off], msg[off+1],
				msg[off+2], msg[off+3]))
		}
		off += rdlen
	}
	return ips, flags&0x0200 != 0, nil
}

// dnsSkipName advances past one (possibly compressed) domain name
// and returns the offset of the following field.
func dnsSkipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("dnsprobe: name overruns message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			// Compression pointer — 2 bytes, name ends here.
			if off+1 >= len(msg) {
				return 0, errors.New("dnsprobe: truncated pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, errors.New("dnsprobe: bad label type")
		default:
			off += 1 + l
		}
	}
}
