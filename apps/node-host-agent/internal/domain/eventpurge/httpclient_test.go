// httpclient_test.go — Config.httpClient: the injected-client
// passthrough, the CA/cert/key file failure ladder, and the
// assembled TLS config (CA pool + client cert + TLS1.2 floor).
package eventpurge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCertPEMs mints a self-signed CA plus a client cert/key pair it
// signed — enough material for LoadX509KeyPair + AppendCertsFromPEM.
func testCertPEMs(t *testing.T) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl,
		&caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert,
		&cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER})
	keyDER, err := x509.MarshalECPrivateKey(cliKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return caPEM, certPEM, keyPEM
}

func TestHTTPClient(t *testing.T) {
	// Injected client is used verbatim — CA/cert files ignored.
	injected := &http.Client{Timeout: time.Second}
	got, err := Config{Client: injected}.httpClient()
	if err != nil || got != injected {
		t.Fatalf("injected client: got=%v err=%v", got, err)
	}

	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Missing CA file.
	if _, err := (Config{CAFile: filepath.Join(dir, "absent.crt")}).httpClient(); err == nil ||
		!strings.Contains(err.Error(), "read CA") {
		t.Fatalf("missing CA err=%v want read CA failure", err)
	}

	// CA file with no PEM blocks.
	badCA := write("bad-ca.crt", []byte("not a pem file\n"))
	if _, err := (Config{CAFile: badCA}).httpClient(); err == nil ||
		!strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("non-PEM CA err=%v want no-PEM failure", err)
	}

	// Valid CA, missing client cert/key.
	caPEM, certPEM, keyPEM := testCertPEMs(t)
	caPath := write("ca.crt", caPEM)
	if _, err := (Config{
		CAFile: caPath, CertFile: filepath.Join(dir, "absent.crt"),
		KeyFile: filepath.Join(dir, "absent.key"),
	}).httpClient(); err == nil || !strings.Contains(err.Error(), "load client cert") {
		t.Fatalf("missing client cert err=%v want load client cert failure", err)
	}

	// Full material — the assembled client carries the CA pool, the
	// client certificate, the TLS1.2 floor and the worker-sized
	// idle pool.
	certPath := write("admin.crt", certPEM)
	keyPath := write("admin.key", keyPEM)
	client, err := (Config{
		CAFile: caPath, CertFile: certPath, KeyFile: keyPath,
		Timeout: 5 * time.Second, Workers: 3,
	}).httpClient()
	if err != nil {
		t.Fatalf("httpClient: %v", err)
	}
	if client.Timeout != 5*time.Second {
		t.Fatalf("Timeout=%v want 5s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport=%T want *http.Transport", client.Transport)
	}
	if tr.MaxIdleConnsPerHost != 3 {
		t.Fatalf("MaxIdleConnsPerHost=%d want 3", tr.MaxIdleConnsPerHost)
	}
	// The transport is a DefaultTransport clone, not a from-scratch
	// struct — ForceAttemptHTTP2 survives, so the custom TLS config
	// does not silently downgrade the pool to HTTP/1.1.
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 lost — custom TLS config disables HTTP/2")
	}
	tlsCfg := tr.TLSClientConfig
	if tlsCfg == nil || tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSClientConfig=%+v want TLS1.2 floor", tlsCfg)
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("RootCAs unset — CA pool not wired")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("Certificates=%d want 1 client cert", len(tlsCfg.Certificates))
	}
}
