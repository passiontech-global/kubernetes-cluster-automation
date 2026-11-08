// probes_tls_test.go — the TLSCertFn default dial: the presented
// leaf certificate comes back from a live TLS listener (insecure by
// design — drift is judged on the presented cert), and dial
// failures surface as errors.
package cdeps

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestTlsDialCertPresentsLeaf(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7777),
		Subject:               pkix.Name{CommonName: "presented-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pairPEM(der),
		pairKeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	ln := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{pair}})
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the conn just long enough for the handshake.
			buf := make([]byte, 16)
			_, _ = c.Read(buf)
			_ = c.Close()
		}
	}()

	got, err := tlsDialCert(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("tlsDialCert err=%v", err)
	}
	if got.SerialNumber.Cmp(big.NewInt(7777)) != 0 {
		t.Fatalf("presented serial=%v want 7777", got.SerialNumber)
	}
	if got.Subject.CommonName != "presented-cert" {
		t.Fatalf("presented CN=%q", got.Subject.CommonName)
	}

	// A dead listener is an error, never a panic.
	if _, err := tlsDialCert(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("dial to a closed port returned nil error")
	}
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func pairPEM(der []byte) []byte {
	return pemEncode("CERTIFICATE", der)
}

func pairKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncode("EC PRIVATE KEY", kb)
}
