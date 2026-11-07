// probes.go — the network liveness probes behind the Config seams:
// the pg-wire StartupMessage check behind PgWireFn (lib.sh
// pg_wire_ok) and the presented-cert TLS dial behind TLSCertFn. The
// HTTP probes (the old probeClient + probeAnyCode and the CP-freeze
// probeHTTP2xx/httpGetInsecure) live in platform/probee — same
// shared insecure client, same semantics.
package cdeps

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// pgAuthOK is the first-response-byte healthy set: 'R' auth request
// / 'S' param status / 'N' notice / 'K' backend key.
const pgAuthOK = "RSNK"

// PGWireOK is the native-Go port of lib.sh pg_wire_ok: send a
// Postgres StartupMessage (user=postgres db=postgres, protocol 3.0)
// and check the first response byte — 'R' auth request / 'S' param
// status / 'N' notice / 'K' backend key = healthy; 'E' error, RST or
// timeout = broken (pgbouncer "server login has been failing").
// The dial is container-side on purpose: the pod is hostNetwork, so
// the DB host:port is reached exactly as the host would reach it.
func PGWireOK(ctx context.Context, hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "5432"
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	params := "user\x00postgres\x00database\x00postgres\x00\x00"
	msg := append([]byte{0, 3, 0, 0}, params...) // 196608 big-endian
	pkt := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(pkt, uint32(len(msg)+4)) // length incl. itself
	pkt = append(pkt, msg...)
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false
	}
	return strings.IndexByte(pgAuthOK, b[0]) >= 0
}

// tlsDialCert returns the leaf certificate addr presents — drift is
// judged on the presented cert, not on chain trust, so the dial is
// insecure by design. It is the TLSCertFn default (the PKI-drift
// domain check consumes the seam).
func tlsDialCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) // drift check wants the presented cert
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificate")
	}
	return state.PeerCertificates[0], nil
}
