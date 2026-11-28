// tls.go — shared TLS peer-certificate dialer for probe seams (cdeps
// PKI drift and wdeps loopback cert probes).
package probee

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

const defaultTLSPeerCertTimeout = 8 * time.Second

// TLSPeerCert dials addr over TCP+TLS with InsecureSkipVerify and
// returns the leaf peer certificate. Callers inspect the presented
// cert directly (loopback/IP endpoints whose SANs do not cover the
// dial target).
func TLSPeerCert(ctx context.Context, addr string, timeout time.Duration) (*x509.Certificate, error) {
	if timeout <= 0 {
		timeout = defaultTLSPeerCertTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{InsecureSkipVerify: true}, // drift/SAN-less probes inspect the presented cert
	}
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("dial did not return a TLS connection")
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("tls peer %s presented no certificates", addr)
	}
	return certs[0], nil
}
