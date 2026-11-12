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
	"errors"
	"net"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
)

// PGWireOK is the pg-wire StartupMessage probe behind PgWireFn —
// the implementation lives in platform/probee (PGWireProbe) so
// every subsystem shares the one wire-format port of lib.sh
// pg_wire_ok.
func PGWireOK(ctx context.Context, hostport string) bool {
	return probee.PGWireProbe(ctx, hostport)
}

// tlsDialCert returns the leaf certificate addr presents — drift is
// judged on the presented cert, not on chain trust, so the dial is
// insecure by design. It is the TLSCertFn default (the PKI-drift
// domain check consumes the seam). The dialer carries the caller's
// ctx via DialContext (tls.DialWithDialer ignores it — a cancelled
// cycle must not leave the dial running).
func tlsDialCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true}, // drift check wants the presented cert
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("dial did not return a TLS connection")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificate")
	}
	return state.PeerCertificates[0], nil
}
